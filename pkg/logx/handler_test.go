package logx

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ctxKey string

func TestContextWithAttrs(t *testing.T) {
	t.Run("nil context handling", func(t *testing.T) {
		var nilCtx context.Context
		ctx := ContextWithAttrs(nilCtx, slog.String("k1", "v1"))
		attrs := AttrsFromContext(ctx)
		require.Len(t, attrs, 1)
		assert.Equal(t, "k1", attrs[0].Key)
		assert.Equal(t, "v1", attrs[0].Value.String())
	})

	t.Run("empty attrs returns original context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxKey("custom"), "val")
		newCtx := ContextWithAttrs(ctx)
		assert.Equal(t, ctx, newCtx)
	})

	t.Run("incremental injection and deduplication", func(t *testing.T) {
		ctx := context.Background()
		ctx = ContextWithAttrs(ctx, slog.String("trace_id", "trace-1"), slog.Int("user_id", 100))
		ctx = ContextWithAttrs(ctx, slog.String("env", "prod"))
		// 再次注入同名 trace_id，应覆盖先前的值
		ctx = ContextWithAttrs(ctx, slog.String("trace_id", "trace-2"))

		attrs := AttrsFromContext(ctx)
		require.Len(t, attrs, 3)

		attrMap := make(map[string]any, len(attrs))
		for _, a := range attrs {
			attrMap[a.Key] = a.Value.Any()
		}

		assert.Equal(t, "trace-2", attrMap["trace_id"])
		assert.Equal(t, int64(100), attrMap["user_id"])
		assert.Equal(t, "prod", attrMap["env"])
	})
}

func TestContextWithTraceID(t *testing.T) {
	ctx := context.Background()
	// 空 traceID 原样返回
	assert.Equal(t, ctx, ContextWithTraceID(ctx, ""))

	newCtx := ContextWithTraceID(ctx, "abc-xyz-123")
	attrs := AttrsFromContext(newCtx)
	require.Len(t, attrs, 1)
	assert.Equal(t, "trace_id", attrs[0].Key)
	assert.Equal(t, "abc-xyz-123", attrs[0].Value.String())
}

func TestContextWithRequestID(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, ctx, ContextWithRequestID(ctx, ""))

	newCtx := ContextWithRequestID(ctx, "req-987")
	attrs := AttrsFromContext(newCtx)
	require.Len(t, attrs, 1)
	assert.Equal(t, "request_id", attrs[0].Key)
	assert.Equal(t, "req-987", attrs[0].Value.String())
}

func TestAttrsFromContext(t *testing.T) {
	var nilCtx context.Context
	assert.Nil(t, AttrsFromContext(nilCtx))
	assert.Nil(t, AttrsFromContext(context.Background()))
}

func TestContextHandler_EndToEnd(t *testing.T) {
	buf := &bytes.Buffer{}
	baseHandler := slog.NewJSONHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	handler := NewContextHandler(baseHandler)
	logger := slog.New(handler)

	assert.Equal(t, baseHandler, handler.Unwrap())
	assert.True(t, handler.Enabled(context.Background(), slog.LevelInfo))

	ctx := context.Background()
	ctx = ContextWithTraceID(ctx, "trace-999")
	ctx = ContextWithAttrs(ctx, slog.String("client_ip", "192.168.1.1"))

	logger.InfoContext(ctx, "order created", slog.String("order_id", "ord-001"))

	var out map[string]any
	err := json.Unmarshal(buf.Bytes(), &out)
	require.NoError(t, err)

	assert.Equal(t, "order created", out["msg"])
	assert.Equal(t, "trace-999", out["trace_id"])
	assert.Equal(t, "192.168.1.1", out["client_ip"])
	assert.Equal(t, "ord-001", out["order_id"])
}

func TestContextHandler_WithAttrsAndGroup(t *testing.T) {
	buf := &bytes.Buffer{}
	baseHandler := slog.NewJSONHandler(buf, nil)
	handler := NewContextHandler(baseHandler)
	logger := slog.New(handler)

	// 测试 WithAttrs
	subLogger := logger.With(slog.String("module", "payment"))
	// 测试 WithGroup
	groupedLogger := subLogger.WithGroup("order_meta")

	ctx := ContextWithTraceID(context.Background(), "trace-grp")
	groupedLogger.InfoContext(ctx, "group message", slog.Int("amount", 50))

	var out map[string]any
	err := json.Unmarshal(buf.Bytes(), &out)
	require.NoError(t, err)

	assert.Equal(t, "group message", out["msg"])
	assert.Equal(t, "payment", out["module"])
	assert.Equal(t, "trace-grp", out["trace_id"]) // 关键验证：上下文属性始终位于日志顶层

	orderMeta, ok := out["order_meta"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(50), orderMeta["amount"])
	assert.Nil(t, orderMeta["trace_id"]) // 关键验证：上下文属性不被污染进业务 group 内部
}

func TestContextHandler_Concurrency(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := slog.New(NewContextHandler(slog.NewJSONHandler(buf, nil)))

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := ContextWithAttrs(context.Background(), slog.Int("worker_id", idx))
			logger.InfoContext(ctx, "worker running")
		}(i)
	}
	wg.Wait()
}

func TestContextWithAttrs_SmallAndLarge(t *testing.T) {
	t.Run("small slice path <= 8", func(t *testing.T) {
		ctx := context.Background()
		ctx = ContextWithAttrs(ctx,
			slog.String("k1", "v1"),
			slog.String("k2", "v2"),
			slog.String("k3", "v3"),
		)
		// 再次注入覆盖 k2，并添加 k4，总数 <= 8
		ctx = ContextWithAttrs(ctx,
			slog.String("k2", "v2-updated"),
			slog.String("k4", "v4"),
		)

		attrs := AttrsFromContext(ctx)
		require.Len(t, attrs, 4)
		attrMap := make(map[string]string)
		for _, a := range attrs {
			attrMap[a.Key] = a.Value.String()
		}
		assert.Equal(t, "v1", attrMap["k1"])
		assert.Equal(t, "v2-updated", attrMap["k2"])
		assert.Equal(t, "v3", attrMap["k3"])
		assert.Equal(t, "v4", attrMap["k4"])
	})

	t.Run("large slice fallback to map > 8", func(t *testing.T) {
		ctx := context.Background()
		// 注入 6 个属性
		ctx = ContextWithAttrs(ctx,
			slog.Int("k1", 1), slog.Int("k2", 2), slog.Int("k3", 3),
			slog.Int("k4", 4), slog.Int("k5", 5), slog.Int("k6", 6),
		)
		// 追加 4 个属性（总数 10 > 8，触发 map 分支），包含对 k3 的更新
		ctx = ContextWithAttrs(ctx,
			slog.Int("k3", 300),
			slog.Int("k7", 7),
			slog.Int("k8", 8),
			slog.Int("k9", 9),
		)

		attrs := AttrsFromContext(ctx)
		require.Len(t, attrs, 9)
		attrMap := make(map[string]int64)
		for _, a := range attrs {
			attrMap[a.Key] = a.Value.Int64()
		}
		assert.Equal(t, int64(300), attrMap["k3"])
		assert.Equal(t, int64(1), attrMap["k1"])
		assert.Equal(t, int64(9), attrMap["k9"])
	})
}

func BenchmarkAttrsFromContext(b *testing.B) {
	ctx := ContextWithAttrs(context.Background(),
		slog.String("trace_id", "trace-bench"),
		slog.Int("user_id", 100),
		slog.String("req_path", "/api/v1/test"),
	)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = AttrsFromContext(ctx)
	}
}

func BenchmarkContextWithAttrs_Small(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ctx := ContextWithAttrs(context.Background(),
			slog.String("trace_id", "trace-bench"),
			slog.Int("user_id", 100),
		)
		_ = ContextWithAttrs(ctx, slog.String("trace_id", "trace-updated"))
	}
}

func BenchmarkContextWithAttrs_Large(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ctx := ContextWithAttrs(context.Background(),
			slog.Int("k1", 1), slog.Int("k2", 2), slog.Int("k3", 3),
			slog.Int("k4", 4), slog.Int("k5", 5), slog.Int("k6", 6),
		)
		_ = ContextWithAttrs(ctx,
			slog.Int("k3", 300), slog.Int("k7", 7), slog.Int("k8", 8), slog.Int("k9", 9),
		)
	}
}
