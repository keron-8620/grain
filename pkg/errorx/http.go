package errorx

type ResponseContext interface {
	AbortWithStatusJSON(code int, jsonObj any)
}

func RespondWithError(c ResponseContext, err error) {
	if c == nil || err == nil {
		return
	}

	rErr, ok := FromError(err)
	if !ok {
		rErr = CodeSystemError.Error().WithCause(err)
	}

	resp := map[string]any{
		"code": rErr.Code.Int(),
		"msg":  rErr.Msg,
		"data": nil,
	}

	if len(rErr.Details) > 0 {
		resp["data"] = rErr.Details
	}

	c.AbortWithStatusJSON(rErr.Code.HTTPStatus(), resp)
}
