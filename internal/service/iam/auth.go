package iam

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"grain/pkg/auth"
	"grain/pkg/cryptoutil"
	"grain/pkg/errorx"
)

// Login 用户登录认证
// @Summary 用户登录
// @Description 用户通过用户名与密码凭证换取访问令牌与刷新令牌
// @Tags IAM/认证管理
// @Accept json
// @Produce json
// @Param request body LoginReq true "登录凭证"
// @Success 200 {object} Response{data=LoginResp} "登录成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "用户名或密码错误"
// @Failure 403 {object} Response "账号已被锁定/禁用"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/auth/login [post]
func (s *Service) Login(c *gin.Context) {
	var req LoginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	result, err := s.biz.Auth.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, LoginResp{
		User:   result.User,
		Tokens: result.TokenPair,
	})
}

// RefreshToken 刷新访问凭证
// @Summary 刷新访问凭证
// @Description 使用有效的刷新令牌 (Refresh Token) 换取新的访问令牌与刷新令牌 (Token Rotation)
// @Tags IAM/认证管理
// @Accept json
// @Produce json
// @Param request body RefreshTokenReq true "刷新令牌请求"
// @Success 200 {object} Response{data=TokenPair} "刷新成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "刷新令牌无效或已过期"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/auth/refresh [post]
func (s *Service) RefreshToken(c *gin.Context) {
	var req RefreshTokenReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	tokens, err := s.biz.Auth.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, tokens)
}

// Logout 用户登出
// @Summary 用户登出
// @Description 撤销当前用户的登录凭证，使当前刷新令牌和所有旧访问令牌失效
// @Tags IAM/认证管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body LogoutReq false "可选刷新令牌"
// @Success 200 {object} Response "登出成功"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/auth/logout [post]
func (s *Service) Logout(c *gin.Context) {
	claims, err := auth.GetJwtClaims(c.Request.Context())
	if err != nil {
		Failure(c, errorx.CodeUnauthorized.Error("未获取到认证上下文"))
		return
	}

	var req LogoutReq
	_ = c.ShouldBindJSON(&req)

	var jti string
	if req.RefreshToken != "" && s.biz.Auth.TokenManager() != nil {
		if refreshClaims, parseErr := s.biz.Auth.TokenManager().VerifyToken(c.Request.Context(), req.RefreshToken); parseErr == nil && refreshClaims != nil {
			jti = refreshClaims.ID
		}
	}

	if err := s.biz.Auth.Logout(c.Request.Context(), claims.UserID, jti); err != nil {
		Failure(c, err)
		return
	}

	SuccessMsg(c, "登出成功", nil)
}

// GetProfile 获取当前登录用户信息
// @Summary 获取当前登录用户信息
// @Description 从当前访问令牌中提取用户上下文并返回用户详情与关联角色
// @Tags IAM/认证管理
// @Security BearerAuth
// @Produce json
// @Success 200 {object} Response{data=User} "获取成功"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 404 {object} Response "用户不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/auth/me [get]
func (s *Service) GetProfile(c *gin.Context) {
	claims, err := auth.GetJwtClaims(c.Request.Context())
	if err != nil {
		Failure(c, errorx.CodeUnauthorized.Error("未获取到认证上下文"))
		return
	}

	user, err := s.biz.User.Get(c.Request.Context(), claims.UserID)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, user)
}

// GetPublicKey 获取 JWT 验签公钥
// @Summary 获取 JWT 验签公钥
// @Description 获取用于客户端或下游服务校验 JWT 令牌签名的公钥及 JWKS 规范定义
// @Tags IAM/认证管理
// @Produce json
// @Success 200 {object} PublicKeyResponse "公钥获取成功"
// @Failure 500 {object} Response "服务器配置异常"
// @Router /api/v1/public-key [get]
func (s *Service) GetPublicKey(c *gin.Context) {
	tm := s.biz.Auth.TokenManager()
	if tm == nil || tm.PublicKey() == nil {
		Failure(c, errorx.CodeConfigError.Error("未配置公钥信息"))
		return
	}

	pub := tm.PublicKey()
	kid := tm.KeyID()
	if kid == "" {
		kid, _ = auth.KeyID(pub)
	}

	jwk, err := auth.PublicKeyToJWK(pub, kid, "RS256")
	if err != nil {
		Failure(c, errorx.CodeSystemError.Error("生成 JWK 失败"))
		return
	}

	active := true
	jwk.Active = &active
	jwks := auth.JSONWebKeySet{Keys: []auth.JSONWebKey{*jwk}}

	pubPEM, err := cryptoutil.MarshalPublicKeyPKIXPEM(pub)
	if err != nil {
		Failure(c, errorx.CodeSystemError.Error("导出 PEM 公钥失败"))
		return
	}

	resp := &auth.PublicKeyResponse{
		JWKS:      jwks,
		PublicKey: string(pubPEM),
		Algorithm: "RS256",
		KeyID:     kid,
		Keys: []auth.PublicKeyEntry{
			{KeyID: kid, PublicKey: string(pubPEM), Active: true},
		},
	}

	c.JSON(http.StatusOK, resp)
}

// GetJWKS 获取标准 JWKS 公钥集
// @Summary 获取 RFC 7517 标准 JWKS 公钥集
// @Description 返回标准 JWKS (JSON Web Key Set) 格式的公钥集合
// @Tags IAM/认证管理
// @Produce json
// @Success 200 {object} JSONWebKeySet "JWKS获取成功"
// @Failure 500 {object} Response "服务器配置异常"
// @Router /.well-known/jwks.json [get]
func (s *Service) GetJWKS(c *gin.Context) {
	tm := s.biz.Auth.TokenManager()
	if tm == nil || tm.PublicKey() == nil {
		Failure(c, errorx.CodeConfigError.Error("未配置公钥信息"))
		return
	}

	pub := tm.PublicKey()
	kid := tm.KeyID()
	if kid == "" {
		kid, _ = auth.KeyID(pub)
	}

	jwk, err := auth.PublicKeyToJWK(pub, kid, "RS256")
	if err != nil {
		Failure(c, errorx.CodeSystemError.Error("生成 JWK 失败"))
		return
	}

	active := true
	jwk.Active = &active
	jwks := auth.JSONWebKeySet{Keys: []auth.JSONWebKey{*jwk}}

	c.JSON(http.StatusOK, jwks)
}
