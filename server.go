package web

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Update Server interface to use functional options and a parameterless Run.
type Server interface {
	Get(path string, handler Handler)
	Post(path string, handler Handler)
	Delete(path string, handler Handler)
	Put(path string, handler Handler)
	Patch(path string, handler Handler)
	Options(path string, handler Handler)
	Head(path string, handler Handler)
	Connect(path string, handler Handler)
	Trace(path string, handler Handler)
	AddRoute(method string, path string, handler Handler)
	RemoveRoute(method string, path string)
	UpdateRoute(method string, path string, handler Handler)
	Group(prefix string) *Group[Handler]
	Request(method string, path string, headers []Header, body io.Reader) Response
	Router() *Router[Handler]
	Run() error
	Use(handlers ...Handler)
}

// Option and option functions
type Option func(*server)

func WithAddress(addr string) Option {
	return func(s *server) {
		s.address = addr
	}
}

func WithDefault404Handler(h Handler) Option {
	return func(s *server) {
		s.default404Handler = h
	}
}

func WithMethodNotAllowedHandler(h Handler) Option {
	return func(s *server) {
		s.defaultMethodNotAllowedHandler = h
	}
}

func WithErrorHandler(h func(Ctx, error) error) Option {
	return func(s *server) {
		s.errorHandler = h
	}
}

// WithSession returns an Option to define a custom SessionManager.
// When provided, the session middleware is automatically inserted.
func WithSession(sm *SessionManager) Option {
	return func(s *server) {
		s.sessionManager = sm
		s.Use(sessionMiddleware)
	}
}

// Extend server struct to add configuration fields.
type server struct {
	handlers                       []Handler
	contextPool                    sync.Pool
	router                         *Router[Handler]
	errorHandler                   func(Ctx, error) error
	sessionManager                 *SessionManager
	address                        string
	default404Handler              Handler
	defaultMethodNotAllowedHandler Handler
}

// NewServer creates a new HTTP server.
func NewServer(options ...Option) Server {
	r := &Router[Handler]{}
	var s *server
	s = &server{
		router: r,
		handlers: []Handler{
			func(c Ctx) error {
				ctx := c.(*context)
				handler := r.LookupNoAlloc(ctx.request.method, ctx.request.path, ctx.request.addParameter)
				// If no handler found, choose the appropriate default.
				if handler == nil {
					if !isRequestMethod(ctx.request.method) {
						return s.defaultMethodNotAllowedHandler(ctx)
					}
					return s.default404Handler(ctx)
				}
				return handler(c)
			},
		},
		// Set our default error handler.
		errorHandler: DefaultErrorHandler,
	}
	// Apply provided options.
	for _, opt := range options {
		opt(s)
	}
	// Set defaults if still nil.
	if s.address == "" {
		s.address = ":8080"
	}
	if s.default404Handler == nil {
		s.default404Handler = Default404Handler
	}
	if s.defaultMethodNotAllowedHandler == nil {
		s.defaultMethodNotAllowedHandler = DefaultMethodNotFoundHandler
	}
	s.contextPool.New = func() any { return s.newContext() }
	return s
}

// Get registers your function to be called when the given GET path has been requested.
func (s *server) Get(path string, handler Handler) {
	s.Router().Add("GET", path, handler)
}

// Add new methods for all HTTP verbs
func (s *server) Post(path string, handler Handler) {
	s.Router().Add("POST", path, handler)
}

func (s *server) Delete(path string, handler Handler) {
	s.Router().Add("DELETE", path, handler)
}

func (s *server) Put(path string, handler Handler) {
	s.Router().Add("PUT", path, handler)
}

func (s *server) Patch(path string, handler Handler) {
	s.Router().Add("PATCH", path, handler)
}

func (s *server) Options(path string, handler Handler) {
	s.Router().Add("OPTIONS", path, handler)
}

func (s *server) Head(path string, handler Handler) {
	s.Router().Add("HEAD", path, handler)
}

func (s *server) Connect(path string, handler Handler) {
	s.Router().Add("CONNECT", path, handler)
}

func (s *server) Trace(path string, handler Handler) {
	s.Router().Add("TRACE", path, handler)
}

// Dynamic route management
func (s *server) AddRoute(method string, path string, handler Handler) {
	s.Router().Add(method, path, handler)
}

func (s *server) RemoveRoute(method string, path string) {
	s.Router().Remove(method, path)
}

func (s *server) UpdateRoute(method string, path string, handler Handler) {
	s.Router().Update(method, path, handler)
}

// Expose the group feature from
func (s *server) Group(prefix string) *Group[Handler] {
	return s.Router().Group(prefix)
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
func (s *server) Run() error {
	listener, err := net.Listen("tcp", s.address)
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
func (s *server) Router() *Router[Handler] {
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
		s.handleRequest(ctx, method, url, conn)
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
			params:  make([]Parameter, 0, 8),
		},
		response: response{
			body:    make([]byte, 0, 1024),
			headers: make([]Header, 0, 8),
			status:  200,
		},
		// session will be set by the middleware.
	}
}

// Handler is a function that deals with the given request/response context.
type Handler func(Ctx) error

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
	params  []Parameter
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
	req.params = append(req.params, Parameter{
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

// Default404Handler sends a default 404 Not Found response.
func Default404Handler(ctx Ctx) error {
	ctx.Status(404)
	return ctx.SendString("404 Not Found")
}

// DefaultMethodNotFoundHandler sends a default 405 Method Not Allowed response.
func DefaultMethodNotFoundHandler(ctx Ctx) error {
	ctx.Status(405)
	return ctx.SendString("405 Method Not Allowed")
}

// DefaultErrorHandler logs the error and sends a default 500 Internal Server Error response.
func DefaultErrorHandler(ctx Ctx, err error) error {
	// Log error details
	log.Printf("Error on %s: %v", ctx.Request().Path(), err)
	ctx.Status(500)
	return ctx.SendString("500 Internal Server Error")
}
