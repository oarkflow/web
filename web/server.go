package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/oarkflow/server/consts"
	"github.com/oarkflow/server/router"
)

// Context is the interface for a request and its response.
type Context interface {
	Send([]byte) error
	Error(...any) error
	Next() error
	Redirect(int, string) error
	Request() Request
	Response() Response
	Status(int) Context
	SendString(string) error
	CSS(body string) error
	CSV(body string) error
	HTML(body string) error
	JS(body string) error
	JSON(object any) error
	Text(body string) error
	XML(body string) error
}

// context contains the request and response data.
type context struct {
	request
	response
	server       *server
	handlerCount uint8
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
func (ctx *context) Status(status int) Context {
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

// Server is the interface for an HTTP server.
type Server interface {
	Get(path string, handler Handler)
	Request(method string, path string, headers []Header, body io.Reader) Response
	Router() *router.Router[Handler]
	Run(address string) error
	Use(handlers ...Handler)
}

// server is an HTTP server.
type server struct {
	handlers     []Handler
	contextPool  sync.Pool
	router       *router.Router[Handler]
	errorHandler func(Context, error)
}

// NewServer creates a new HTTP server.
func NewServer() Server {
	r := &router.Router[Handler]{}
	s := &server{
		router: r,
		handlers: []Handler{
			func(c Context) error {
				ctx := c.(*context)
				handler := r.LookupNoAlloc(ctx.request.method, ctx.request.path, ctx.request.addParameter)

				if handler == nil {
					ctx.SetStatus(404)
					return nil
				}

				return handler(c)
			},
		},
		errorHandler: func(ctx Context, err error) {
			log.Println(ctx.Request().Path(), err)
		},
	}

	s.contextPool.New = func() any { return s.newContext() }
	return s
}

// Get registers your function to be called when the given GET path has been requested.
func (s *server) Get(path string, handler Handler) {
	s.Router().Add("GET", path, handler)
}

// Request performs a synthetic request and returns the response.
// This function keeps the response in memory so it's slightly slower than a real request.
// However it is very useful inside tests where you don't want to spin up a real web server.
func (s *server) Request(method string, url string, headers []Header, body io.Reader) Response {
	ctx := s.newContext()
	ctx.request.headers = headers
	s.handleRequest(ctx, method, url, io.Discard)
	return ctx.Response()
}

// Run starts the server on the given address.
func (s *server) Run(address string) error {
	listener, err := net.Listen("tcp", address)

	if err != nil {
		return err
	}

	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()

			if err != nil {
				continue
			}

			go s.handleConnection(conn)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	return nil
}

// Router returns the router used by the server.
func (s *server) Router() *router.Router[Handler] {
	return s.router
}

// Use adds handlers to your handlers chain.
func (s *server) Use(handlers ...Handler) {
	last := s.handlers[len(s.handlers)-1]
	s.handlers = append(s.handlers[:len(s.handlers)-1], handlers...)
	s.handlers = append(s.handlers, last)
}

// handleConnection handles an accepted connection.
func (s *server) handleConnection(conn net.Conn) {
	var (
		ctx    = s.contextPool.Get().(*context)
		method string
		url    string
		close  bool
	)

	ctx.reader.Reset(conn)

	defer conn.Close()
	defer s.contextPool.Put(ctx)

	for !close {
		// Read the HTTP request line
		message, err := ctx.reader.ReadString('\n')

		if err != nil {
			return
		}

		space := strings.IndexByte(message, ' ')

		if space <= 0 {
			io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
			return
		}

		method = message[:space]

		if !isRequestMethod(method) {
			io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
			return
		}

		lastSpace := strings.LastIndexByte(message, ' ')

		if lastSpace == space {
			lastSpace = len(message) - len("\r\n")
		}

		space += 1

		if space > lastSpace {
			io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
			return
		}

		url = message[space:lastSpace]

		// Add headers until we meet an empty line
		for {
			message, err = ctx.reader.ReadString('\n')

			if err != nil {
				return
			}

			if message == "\r\n" {
				break
			}

			colon := strings.IndexByte(message, ':')

			if colon <= 0 {
				continue
			}

			if colon > len(message)-4 {
				continue
			}

			key := message[:colon]
			value := message[colon+2 : len(message)-2]

			ctx.request.headers = append(ctx.request.headers, Header{
				Key:   key,
				Value: value,
			})

			if value == "close" && strings.EqualFold(key, "connection") {
				close = true
			}
		}

		// Handle the request
		s.handleRequest(ctx, method, url, conn)

		// Clean up the context
		ctx.request.headers = ctx.request.headers[:0]
		ctx.request.body = ctx.request.body[:0]
		ctx.response.headers = ctx.response.headers[:0]
		ctx.response.body = ctx.response.body[:0]
		ctx.params = ctx.params[:0]
		ctx.handlerCount = 0
		ctx.status = 200
	}
}

// handleRequest handles the given request.
func (s *server) handleRequest(ctx *context, method string, url string, writer io.Writer) {
	ctx.method = method
	ctx.scheme, ctx.host, ctx.path, ctx.query = parseURL(url)

	err := s.handlers[0](ctx)

	if err != nil {
		s.errorHandler(ctx, err)
	}

	tmp := bytes.Buffer{}
	tmp.WriteString("HTTP/1.1 ")
	tmp.WriteString(strconv.Itoa(int(ctx.status)))
	tmp.WriteString("\r\nContent-Length: ")
	tmp.WriteString(strconv.Itoa(len(ctx.response.body)))
	tmp.WriteString("\r\n")

	for _, header := range ctx.response.headers {
		tmp.WriteString(header.Key)
		tmp.WriteString(": ")
		tmp.WriteString(header.Value)
		tmp.WriteString("\r\n")
	}

	tmp.WriteString("\r\n")
	tmp.Write(ctx.response.body)
	writer.Write(tmp.Bytes())
}

// newContext allocates a new context with the default state.
func (s *server) newContext() *context {
	return &context{
		server: s,
		request: request{
			reader:  bufio.NewReader(nil),
			body:    make([]byte, 0),
			headers: make([]Header, 0, 8),
			params:  make([]router.Parameter, 0, 8),
		},
		response: response{
			body:    make([]byte, 0, 1024),
			headers: make([]Header, 0, 8),
			status:  200,
		},
	}
}

// Handler is a function that deals with the given request/response context.
type Handler func(Context) error

// Header is used to store HTTP headers.
type Header struct {
	Key   string
	Value string
}

// isRequestMethod returns true if the given string is a valid HTTP request method.
func isRequestMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH":
		return true
	default:
		return false
	}
}

// parseURL parses a URL and returns the scheme, host, path and query.
func parseURL(url string) (scheme string, host string, path string, query string) {
	schemePos := strings.Index(url, "://")

	if schemePos != -1 {
		scheme = url[:schemePos]
		url = url[schemePos+len("://"):]
	}

	pathPos := strings.IndexByte(url, '/')

	if pathPos != -1 {
		host = url[:pathPos]
		url = url[pathPos:]
	}

	queryPos := strings.IndexByte(url, '?')

	if queryPos != -1 {
		path = url[:queryPos]
		query = url[queryPos+1:]
		return
	}

	path = url
	return
}

// Request is an interface for HTTP requests.
type Request interface {
	Header(string) string
	Host() string
	Method() string
	Path() string
	Scheme() string
	Param(string) string
}

// request represents the HTTP request used in the given context.
type request struct {
	reader  *bufio.Reader
	scheme  string
	host    string
	method  string
	path    string
	query   string
	headers []Header
	body    []byte
	params  []router.Parameter
}

// Header returns the header value for the given key.
func (req *request) Header(key string) string {
	for _, header := range req.headers {
		if header.Key == key {
			return header.Value
		}
	}

	return ""
}

// Host returns the requested host.
func (req *request) Host() string {
	return req.host
}

// Method returns the request method.
func (req *request) Method() string {
	return req.method
}

// Param retrieves a parameter.
func (req *request) Param(name string) string {
	for i := range len(req.params) {
		p := req.params[i]

		if p.Key == name {
			return p.Value
		}
	}

	return ""
}

// Path returns the requested path.
func (req *request) Path() string {
	return req.path
}

// Scheme returns either `http`, `https` or an empty string.
func (req request) Scheme() string {
	return req.scheme
}

// addParameter adds a new parameter to the request.
func (req *request) addParameter(key string, value string) {
	req.params = append(req.params, router.Parameter{
		Key:   key,
		Value: value,
	})
}

// Response is the interface for an HTTP response.
type Response interface {
	io.Writer
	io.StringWriter
	Body() []byte
	Header(string) string
	SetHeader(key string, value string)
	SetBody([]byte)
	SetStatus(int)
	Status() int
}

// response represents the HTTP response used in the given context.
type response struct {
	body    []byte
	headers []Header
	status  uint16
}

// Body returns the response body.
func (res *response) Body() []byte {
	return res.body
}

// Header returns the header value for the given key.
func (res *response) Header(key string) string {
	for _, header := range res.headers {
		if header.Key == key {
			return header.Value
		}
	}

	return ""
}

// SetHeader sets the header value for the given key.
func (res *response) SetHeader(key string, value string) {
	for i, header := range res.headers {
		if header.Key == key {
			res.headers[i].Value = value
			return
		}
	}

	res.headers = append(res.headers, Header{Key: key, Value: value})
}

// SetBody replaces the response body with the new contents.
func (res *response) SetBody(body []byte) {
	res.body = body
}

// SetStatus sets the HTTP status code.
func (res *response) SetStatus(status int) {
	res.status = uint16(status)
}

// Status returns the HTTP status code.
func (res *response) Status() int {
	return int(res.status)
}

// Write implements the io.Writer interface.
func (res *response) Write(body []byte) (int, error) {
	res.body = append(res.body, body...)
	return len(body), nil
}

// WriteString implements the io.StringWriter interface.
func (res *response) WriteString(body string) (int, error) {
	res.body = append(res.body, body...)
	return len(body), nil
}
