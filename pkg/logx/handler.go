package logx

import (
	"context"
	"log/slog"
)

type attrsKey struct{}

const smallAttrsThreshold = 8

// ContextWithAttrs 将 slog.Attr 属性存入 context 中
// 若已存在相同 key，后注入的属性将覆盖先前注入的属性（Key 去重）
func ContextWithAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(attrs) == 0 {
		return ctx
	}

	old := AttrsFromContext(ctx)
	totalLen := len(old) + len(attrs)

	// 快速路径：小切片（<= 8）线性扫描，消除 map 堆分配与哈希计算开销
	if totalLen <= smallAttrsThreshold {
		merged := make([]slog.Attr, len(old), totalLen)
		copy(merged, old)
		for _, a := range attrs {
			found := false
			for i := range merged {
				if merged[i].Key == a.Key {
					merged[i] = a
					found = true
					break
				}
			}
			if !found {
				merged = append(merged, a)
			}
		}
		return context.WithValue(ctx, attrsKey{}, merged)
	}

	// 慢速路径：大集合 fallback 到 map 查表
	merged := make([]slog.Attr, len(old), totalLen)
	copy(merged, old)
	keyIndex := make(map[string]int, totalLen)
	for i, a := range merged {
		keyIndex[a.Key] = i
	}

	for _, a := range attrs {
		if idx, exists := keyIndex[a.Key]; exists {
			merged[idx] = a
		} else {
			keyIndex[a.Key] = len(merged)
			merged = append(merged, a)
		}
	}

	return context.WithValue(ctx, attrsKey{}, merged)
}

// ContextWithTraceID 便捷注入 trace_id 属性到 context 中
func ContextWithTraceID(ctx context.Context, traceID string) context.Context {
	if traceID == "" {
		return ctx
	}
	return ContextWithAttrs(ctx, slog.String("trace_id", traceID))
}

// ContextWithRequestID 便捷注入 request_id 属性到 context 中
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	if requestID == "" {
		return ctx
	}
	return ContextWithAttrs(ctx, slog.String("request_id", requestID))
}

// AttrsFromContext 从 context 中取出 slog.Attr 切片（只读视图，零堆分配）
func AttrsFromContext(ctx context.Context) []slog.Attr {
	if ctx == nil {
		return nil
	}
	attrs, ok := ctx.Value(attrsKey{}).([]slog.Attr)
	if !ok || len(attrs) == 0 {
		return nil
	}
	return attrs
}

type handlerStep struct {
	group string
	attrs []slog.Attr
}

// ContextHandler 包装底层 slog.Handler，自动提取并注入 context 中的 Attr
// 具备 Group 隔离保证：当上层调用 WithGroup 时，来自 Context 的顶层属性仍旧保持在日志 Root 顶层
type ContextHandler struct {
	root     slog.Handler
	inner    slog.Handler
	chain    []handlerStep
	levelVar *slog.LevelVar
}

// NewContextHandler 创建 ContextHandler 实例，可选关联动态级别控制器 levelVar
func NewContextHandler(inner slog.Handler, levelVar ...*slog.LevelVar) *ContextHandler {
	var lv *slog.LevelVar
	if len(levelVar) > 0 {
		lv = levelVar[0]
	}
	if ch, ok := inner.(*ContextHandler); ok {
		if lv != nil {
			ch.levelVar = lv
		}
		return ch
	}
	return &ContextHandler{
		root:     inner,
		inner:    inner,
		levelVar: lv,
	}
}

// LevelVar 返回绑定的动态日志级别控制器
func (h *ContextHandler) LevelVar() *slog.LevelVar {
	return h.levelVar
}

func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := AttrsFromContext(ctx)
	if len(attrs) == 0 {
		return h.inner.Handle(ctx, r)
	}

	// 快速路径：未添加任何 Group 包装，直接追加到 record（零额外分配）
	if len(h.chain) == 0 {
		r.AddAttrs(attrs...)
		return h.inner.Handle(ctx, r)
	}

	// 存在活跃 Group：将 context 属性注入到 root 顶层，并重放 chain，确保链路属性不被污染进业务 group 内部
	target := h.root.WithAttrs(attrs)
	for _, step := range h.chain {
		if step.group != "" {
			target = target.WithGroup(step.group)
		} else if len(step.attrs) > 0 {
			target = target.WithAttrs(step.attrs)
		}
	}
	return target.Handle(ctx, r)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	if len(h.chain) == 0 {
		newRoot := h.root.WithAttrs(attrs)
		return &ContextHandler{
			root:     newRoot,
			inner:    newRoot,
			levelVar: h.levelVar,
		}
	}

	newChain := make([]handlerStep, len(h.chain), len(h.chain)+1)
	copy(newChain, h.chain)
	newChain = append(newChain, handlerStep{attrs: attrs})

	return &ContextHandler{
		root:     h.root,
		inner:    h.inner.WithAttrs(attrs),
		chain:    newChain,
		levelVar: h.levelVar,
	}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}

	newChain := make([]handlerStep, len(h.chain), len(h.chain)+1)
	copy(newChain, h.chain)
	newChain = append(newChain, handlerStep{group: name})

	return &ContextHandler{
		root:     h.root,
		inner:    h.inner.WithGroup(name),
		chain:    newChain,
		levelVar: h.levelVar,
	}
}

// Unwrap 返回被包装的底层 slog.Handler
func (h *ContextHandler) Unwrap() slog.Handler {
	return h.inner
}
