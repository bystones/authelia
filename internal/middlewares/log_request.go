package middlewares

import (
	"fmt"
	"strings"

	"github.com/valyala/fasthttp"
)

// LogRequest provides trace logging for all requests.
func LogRequest(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		log := NewRequestLogger(ctx)

		log.Trace("Request hit")

		var headers []string

		ctx.Request.Header.VisitAll(func(key, value []byte) {
			headers = append(headers, fmt.Sprintf("%s=%s", key, value))
		})

		log.WithField("headers", strings.Join(headers, " ")).Trace("Request Headers")

		next(ctx)

		log.Tracef("Replied (status=%d)", ctx.Response.StatusCode())

		headers = []string{}

		ctx.Response.Header.VisitAll(func(key, value []byte) {
			headers = append(headers, fmt.Sprintf("%s=%s", key, value))
		})

		log.WithField("headers", strings.Join(headers, " ")).Trace("Response Headers")
	}
}
