package web

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"

	"github.com/oarkflow/web/consts"
)

// Ctx is the interface for a request and its response.
type Ctx interface {
	Send([]byte) error
	Error(...any) error
	Next() error
	Redirect(int, string) error
	Request() Request
	Response() Response
	Status(int) Ctx
	SendString(string) error
	CSS(body string) error
	CSV(body string) error
	HTML(body string) error
	JS(body string) error
	JSON(object any) error
	Text(body string) error
	XML(body string) error
	Session() *Session
	GetCookie(name string) string
	SetCookie(cookie *Cookie) error
	SendFile(filePath string) error
}

// context contains the request and response data.
type context struct {
	request
	response
	server       *server
	handlerCount uint8
	session      *Session
	rawConn      net.Conn // added to store underlying connection
	hijacked     bool     // if true, do not close connection in HTTP handler
}

// Send adds the raw byte slice to the response body.
func (ctx *context) Send(body []byte) error {
	ctx.response.body = append(ctx.response.body, body...)
	return nil
}

// Error provides a convenient way to wrap multiple errors.
func (ctx *context) Error(messages ...any) error {
	var combined []error

	for _, msg := range messages {
		switch err := msg.(type) {
		case error:
			combined = append(combined, err)
		case string:
			combined = append(combined, errors.New(err))
		}
	}

	return errors.Join(combined...)
}

// Next executes the next handler in the middleware chain.
func (ctx *context) Next() error {
	ctx.handlerCount++
	return ctx.server.handlers[ctx.handlerCount](ctx)
}

// Redirect redirects the client to a different location
// with the specified status code.
func (ctx *context) Redirect(status int, location string) error {
	ctx.response.SetStatus(status)
	ctx.response.SetHeader("Location", location)
	return nil
}

// Request returns the HTTP request.
func (ctx *context) Request() Request {
	return &ctx.request
}

// Response returns the HTTP response.
func (ctx *context) Response() Response {
	return &ctx.response
}

// Status sets the HTTP status of the response
// and returns the context for method chaining.
func (ctx *context) Status(status int) Ctx {
	ctx.response.SetStatus(status)
	return ctx
}

// SendString adds the given string to the response body.
func (ctx *context) SendString(body string) error {
	ctx.response.body = append(ctx.response.body, body...)
	return nil
}

// CSS sends the body with the content type set to `text/css`.
func (ctx *context) CSS(body string) error {
	ctx.Response().SetHeader(consts.HeaderContentType, consts.HeaderMimeTypeCSS)
	return ctx.SendString(body)
}

// CSV sends the body with the content type set to `text/csv`.
func (ctx *context) CSV(body string) error {
	ctx.Response().SetHeader(consts.HeaderContentType, consts.HeaderMimeTypeCSV)
	return ctx.SendString(body)
}

// HTML sends the body with the content type set to `text/html`.
func (ctx *context) HTML(body string) error {
	ctx.Response().SetHeader(consts.HeaderContentType, consts.HeaderMimeTypeHTMLUTF8)
	return ctx.SendString(body)
}

// JS sends the body with the content type set to `text/javascript`.
func (ctx *context) JS(body string) error {
	ctx.Response().SetHeader(consts.HeaderContentType, consts.HeaderMimeTypeJS)
	return ctx.SendString(body)
}

// JSON encodes the object in JSON format and sends it with the content type set to `application/json`.
func (ctx *context) JSON(object any) error {
	ctx.Response().SetHeader(consts.HeaderContentType, consts.HeaderMimeTypeJSONUTF8)
	return json.NewEncoder(ctx.Response()).Encode(object)
}

// Text sends the body with the content type set to `text/plain`.
func (ctx *context) Text(body string) error {
	ctx.Response().SetHeader(consts.HeaderContentType, consts.HeaderMimeTypeTextUTF8)
	return ctx.SendString(body)
}

// XML sends the body with the content type set to `text/xml`.
func (ctx *context) XML(body string) error {
	ctx.Response().SetHeader(consts.HeaderContentType, consts.HeaderMimeTypeXML)
	return ctx.SendString(body)
}

// SendFile serves a file or directory listing at the given file system path.
func (ctx *context) SendFile(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		ctx.Status(404)
		return ctx.SendString("404 Not Found")
	}
	if info.IsDir() {
		entries, err := os.ReadDir(filePath)
		if err != nil {
			ctx.Status(500)
			return ctx.SendString("500 Internal Server Error")
		}
		html := "<html><head><meta charset='utf-8'><title>Directory Listing</title></head><body>"
		html += "<h1>Directory Listing of " + filePath + "</h1><ul>"
		for _, entry := range entries {
			html += "<li>" + entry.Name() + "</li>"
		}
		html += "</ul></body></html>"
		ctx.Response().SetHeader("Content-Type", "text/html")
		return ctx.SendString(html)
	} else {
		f, err := os.Open(filePath)
		if err != nil {
			ctx.Status(500)
			return ctx.SendString("500 Internal Server Error")
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			ctx.Status(500)
			return ctx.SendString("500 Internal Server Error")
		}
		return ctx.Send(data)
	}
}
