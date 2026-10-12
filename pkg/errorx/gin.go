package errorx

type ResponseContext interface {
	AbortWithStatusJSON(code int, jsonObj any)
}

func RespondWithError(c ResponseContext, err *Error) {
	if c == nil || err == nil {
		return
	}

	resp := map[string]any{
		"code": err.Code.Int(),
		"msg":  err.Msg,
		"data": nil,
	}

	if len(err.Details) > 0 {
		resp["data"] = err.Details
	}

	c.AbortWithStatusJSON(err.Code.HTTPStatus(), resp)
}
