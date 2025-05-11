package web

import (
	"crypto/subtle"
	"strconv"
	"strings"
)

func (ctx *context) Session() *Session {
	return ctx.session
}

func (ctx *context) GetCookie(name string) string {
	// Look for Cookie header and parse
	for _, header := range ctx.request.headers {
		if strings.EqualFold(header.Key, "Cookie") {
			// simple cookie parsing: cookie1=value1; cookie2=value2
			cookies := strings.Split(header.Value, ";")
			for _, c := range cookies {
				parts := strings.SplitN(strings.TrimSpace(c), "=", 2)
				if len(parts) == 2 && subtle.ConstantTimeCompare([]byte(parts[0]), []byte(name)) == 1 {
					return parts[1]
				}
			}
		}
	}
	return ""
}

func (ctx *context) SetCookie(cookie *Cookie) error {
	// set the Set-Cookie header; support multiple cookies if needed.
	existing := ctx.response.Header("Set-Cookie")
	c := cookie.String()
	if existing != "" {
		c = existing + "\r\nSet-Cookie: " + c
	}
	ctx.response.SetHeader("Set-Cookie", c)
	return nil
}

type Cookie struct {
	Name     string
	Value    string
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HttpOnly bool
}

func (c *Cookie) String() string {
	// Build cookie string per RFC 6265.
	s := c.Name + "=" + c.Value
	if c.Path != "" {
		s += "; Path=" + c.Path
	}
	if c.Domain != "" {
		s += "; Domain=" + c.Domain
	}
	if c.MaxAge > 0 {
		s += "; Max-Age=" + strconv.Itoa(c.MaxAge)
	}
	if c.Secure {
		s += "; Secure"
	}
	if c.HttpOnly {
		s += "; HttpOnly"
	}
	return s
}

// --- Add session middleware ---
func sessionMiddleware(ctx Ctx) error {
	c := ctx.(*context)
	// Load (or create) session using the session manager.
	c.server.sessionManager.LoadSession(c)
	return c.Next()
}
