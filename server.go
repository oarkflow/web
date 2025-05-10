package main

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var contextPool = sync.Pool{New: func() interface{} { return new(Context) }}

type HandlerFunc func(*Context) error

type Context struct {
	Writer   http.ResponseWriter
	Request  *http.Request
	Params   map[string]string
	index    int
	handlers []HandlerFunc
	mu       sync.Mutex
}

func (c *Context) Next() error {
	c.index++
	if c.index < len(c.handlers) {
		return c.handlers[c.index](c)
	}
	return nil
}

func (c *Context) Abort() {
	c.index = len(c.handlers)
}

func (c *Context) JSON(status int, v interface{}) error {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(status)
	return json.NewEncoder(c.Writer).Encode(v)
}

func (c *Context) XML(status int, v interface{}) error {
	c.Writer.Header().Set("Content-Type", "application/xml")
	c.Writer.WriteHeader(status)
	return xml.NewEncoder(c.Writer).Encode(v)
}

func (c *Context) BindJSON(v interface{}) error {
	if ct := c.Request.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		return errors.New("invalid content-type")
	}
	return json.NewDecoder(c.Request.Body).Decode(v)
}

func (c *Context) Send(data []byte) error {
	_, err := c.Writer.Write(data)
	return err
}

func (c *Context) SendString(s string) error {
	c.Writer.Header().Set("Content-Type", "text/plain")
	return c.Send([]byte(s))
}

func (c *Context) HTML(status int, html string) error {
	c.Writer.Header().Set("Content-Type", "text/html")
	c.Writer.WriteHeader(status)
	return c.SendString(html)
}

func (c *Context) Param(name string) string {
	return c.Params[name]
}

func (c *Context) Query(name, def string) string {
	if v := c.Request.URL.Query().Get(name); v != "" {
		return v
	}
	return def
}

func (c *Context) Cookie(name string) (string, error) {
	cookie, err := c.Request.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func (c *Context) SetCookie(cookie *http.Cookie) error {
	http.SetCookie(c.Writer, cookie)
	return nil
}

func (c *Context) FileForm(key string) (*multipart.FileHeader, error) {
	c.Request.ParseMultipartForm(32 << 20)
	if c.Request.MultipartForm == nil || c.Request.MultipartForm.File == nil {
		return nil, errors.New("no multipart form")
	}
	files := c.Request.MultipartForm.File[key]
	if len(files) == 0 {
		return nil, errors.New("file not found")
	}
	return files[0], nil
}

type Router struct {
	trees            map[string]*node
	globalMW         []HandlerFunc
	notFound         HandlerFunc
	methodNotAllowed HandlerFunc
	errorHandler     func(*Context, error)
	mu               sync.RWMutex
}

type node struct {
	segment   string
	isWild    bool
	paramName string
	optional  bool
	regex     *regexp.Regexp
	children  []*node
	handlers  map[string][]HandlerFunc
}

func NewRouter() *Router {
	return &Router{
		trees: make(map[string]*node),
		notFound: func(c *Context) error {
			c.Writer.WriteHeader(404)
			c.Writer.Write([]byte("404 page not found"))
			return nil
		},
		methodNotAllowed: func(c *Context) error {
			c.Writer.WriteHeader(405)
			c.Writer.Write([]byte("405 method not allowed"))
			return nil
		},
		errorHandler: DefaultErrorHandler,
	}
}

func (r *Router) Use(mw ...HandlerFunc) {
	r.globalMW = append(r.globalMW, mw...)
}

func (r *Router) addRoute(method, pattern string, mws []HandlerFunc, handler HandlerFunc) {
	root, ok := r.trees[method]
	if !ok {
		root = &node{handlers: make(map[string][]HandlerFunc)}
		r.trees[method] = root
	}
	segments := strings.Split(strings.Trim(pattern, "/"), "/")
	current := root
	for _, seg := range segments {
		var nseg string
		var isWild, optional bool
		var paramName string
		var regex *regexp.Regexp
		if seg == "" {
			continue
		}
		if seg[0] == '*' {
			isWild = true
			paramName = seg[1:]
			nseg = "*"
		} else if seg[0] == '{' && seg[len(seg)-1] == '}' {
			inner := seg[1 : len(seg)-1]
			if strings.HasSuffix(inner, "?") {
				optional = true
				inner = inner[:len(inner)-1]
			}
			parts := strings.SplitN(inner, ":", 2)
			paramName = parts[0]
			isWild = true
			nseg = "{}"
			if len(parts) == 2 {
				regex = regexp.MustCompile("^" + parts[1] + "$")
			}
		} else {
			nseg = seg
		}
		var child *node
		for _, c := range current.children {
			if c.segment == nseg && c.isWild == isWild && c.paramName == paramName && c.optional == optional {
				child = c
				break
			}
		}
		if child == nil {
			child = &node{
				segment:   nseg,
				isWild:    isWild,
				paramName: paramName,
				optional:  optional,
				regex:     regex,
				handlers:  make(map[string][]HandlerFunc),
			}
			current.children = append(current.children, child)
		}
		current = child
	}
	current.handlers[method] = append(r.globalMW, mws...)
	current.handlers[method] = append(current.handlers[method], handler)
}

func (r *Router) matchChild(n *node, seg string) *node {
	for _, c := range n.children {
		if c.isWild {
			if c.regex != nil && !c.regex.MatchString(seg) {
				continue
			}
			return c
		}
		if c.segment == seg {
			return c
		}
	}
	return nil
}

func (r *Router) Handle(method, pattern string, mws []HandlerFunc, handler HandlerFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addRoute(method, pattern, mws, handler)
}

type Group struct {
	prefix string
	mw     []HandlerFunc
	router *Router
}

func (r *Router) Group(prefix string, mws ...HandlerFunc) *Group {
	return &Group{prefix: prefix, mw: mws, router: r}
}

func (g *Group) Handle(method, pattern string, mws []HandlerFunc, handler HandlerFunc) {
	full := path.Join(g.prefix, pattern)
	all := append(g.mw, mws...)
	g.router.Handle(method, full, all, handler)
}

func (g *Group) GET(pattern string, mws []HandlerFunc, handler HandlerFunc) {
	g.Handle("GET", pattern, mws, handler)
}

func (r *Router) search(n *node, segs []string, params map[string]string, method string) ([]HandlerFunc, bool) {
	if len(segs) == 0 {
		if h, ok := n.handlers[method]; ok {
			return h, true
		}
		for _, c := range n.children {
			if c.optional {
				if h, ok := r.search(c, segs, params, method); ok {
					return h, true
				}
			}
		}
		return nil, false
	}
	for _, c := range n.children {
		if c.isWild {
			if c.regex != nil && !c.regex.MatchString(segs[0]) {
				if c.optional {
					if h, ok := r.search(c, segs, params, method); ok {
						return h, true
					}
				}
				continue
			}
			params[c.paramName] = segs[0]
			return c.handlers[method], true
		}
		if c.segment == segs[0] {
			if h, ok := r.search(c, segs[1:], params, method); ok {
				return h, true
			}
		}
	}
	return nil, false
}

func (r *Router) matchPattern(n *node, segs []string) bool {
	if len(segs) == 0 {
		return len(n.handlers) > 0
	}
	for _, c := range n.children {
		if c.isWild {
			if c.regex != nil && !c.regex.MatchString(segs[0]) {
				if c.optional && r.matchPattern(c, segs) {
					return true
				}
				continue
			}
			return true
		} else if c.segment == segs[0] {
			if r.matchPattern(c, segs[1:]) {
				return true
			}
		}
	}
	return false
}

type responseWriter struct {
	http.ResponseWriter
	headerWritten bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.headerWritten {
		rw.headerWritten = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rw := &responseWriter{ResponseWriter: w}
	method := req.Method
	pathStr := strings.Trim(req.URL.Path, "/")
	var segs []string
	if pathStr != "" {
		segs = strings.Split(pathStr, "/")
	}
	ctx := contextPool.Get().(*Context)
	ctx.Writer = rw
	ctx.Request = req
	ctx.Params = make(map[string]string)
	ctx.index = -1
	if root, ok := r.trees[method]; ok {
		if h, ok := r.search(root, segs, ctx.Params, method); ok {
			ctx.handlers = h
			defer func() {
				if rec := recover(); rec != nil {
					rw.WriteHeader(500)
					fmt.Fprintf(rw, "panic: %v", rec)
				}
				// Reset and put back to pool
				ctx.handlers = nil
				ctx.Params = nil
				contextPool.Put(ctx)
			}()
			if err := ctx.Next(); err != nil {
				DefaultErrorHandler(ctx, err)
			}
			return
		}
	}
	for m, root := range r.trees {
		if m == method {
			continue
		}
		if r.matchPattern(root, segs) {
			DefaultMethodNotAllowedHandler(&Context{Writer: w, Request: req})
			return
		}
	}
	DefaultNotFoundHandler(&Context{Writer: w, Request: req})
}

func DefaultErrorHandler(c *Context, err error) {
	http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
}

func DefaultNotFoundHandler(c *Context) error {
	c.Writer.WriteHeader(404)
	c.Writer.Write([]byte("404 page not found"))
	return nil
}

func DefaultMethodNotAllowedHandler(c *Context) error {
	c.Writer.WriteHeader(405)
	c.Writer.Write([]byte("405 method not allowed"))
	return nil
}

func Recovery() HandlerFunc {
	return func(c *Context) error {
		defer func() {
			if rec := recover(); rec != nil {
				c.Abort()
				DefaultErrorHandler(c, fmt.Errorf("panic: %v", rec))
			}
		}()
		return c.Next()
	}
}

func Logger() HandlerFunc {
	return func(c *Context) error {
		start := time.Now()
		err := c.Next()
		log.Printf("%s %s %d %s", c.Request.Method, c.Request.URL.Path, http.StatusOK, time.Since(start))
		return err
	}
}

func CORS() HandlerFunc {
	return func(c *Context) error {
		h := c.Writer.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if c.Request.Method == "OPTIONS" {
			c.Writer.WriteHeader(204)
			return nil
		}
		return c.Next()
	}
}

func RateLimiter(rps int) HandlerFunc {
	ticker := time.NewTicker(time.Second / time.Duration(rps))
	return func(c *Context) error {
		<-ticker.C
		return c.Next()
	}
}

func Gzip() HandlerFunc {
	return func(c *Context) error {
		if !strings.Contains(c.Request.Header.Get("Accept-Encoding"), "gzip") {
			return c.Next()
		}
		c.Writer.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(c.Writer)
		defer gz.Close()
		gzw := &gzipResponseWriter{Writer: gz, ResponseWriter: c.Writer}
		c.Writer = gzw
		return c.Next()
	}
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func JWTAuth(secret []byte) HandlerFunc {
	return func(c *Context) error {
		auth := c.Request.Header.Get("Authorization")
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Writer.WriteHeader(401)
			return errors.New("unauthorized")
		}
		token := parts[1]
		parts = strings.Split(token, ".")
		if len(parts) != 3 {
			c.Writer.WriteHeader(401)
			return errors.New("unauthorized")
		}
		sig := hmac.New(sha256.New, secret)
		sig.Write([]byte(parts[0] + "." + parts[1]))
		if !hmac.Equal(sig.Sum(nil), []byte(parts[2])) {
			c.Writer.WriteHeader(401)
			return errors.New("unauthorized")
		}
		return c.Next()
	}
}

func SecurityHeaders() HandlerFunc {
	return func(c *Context) error {
		h := c.Writer.Header()
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Frame-Options", "DENY")
		return c.Next()
	}
}

func RequestSizeLimit(max int64) HandlerFunc {
	return func(c *Context) error {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		return c.Next()
	}
}

func CSRFProtection(token string) HandlerFunc {
	return func(c *Context) error {
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" || c.Request.Method == "DELETE" {
			if c.Request.Header.Get("X-CSRF-Token") != token {
				c.Writer.WriteHeader(403)
				return errors.New("csrf token mismatch")
			}
		}
		return c.Next()
	}
}

func HealthCheck() HandlerFunc {
	return func(c *Context) error {
		return c.JSON(200, map[string]string{"status": "healthy"})
	}
}

func mai1n() {
	http.HandleFunc("/", HelloServer)
	http.ListenAndServe(":8080", nil)
}

func HelloServer(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the home page!")
}

func main() {
	router := NewRouter()
	// router.Use(Recovery(), Logger(), CORS(), SecurityHeaders(), RateLimiter(10), Gzip(), RequestSizeLimit(1<<20), CSRFProtection("fixedtoken"))
	router.Handle("GET", "/", nil, func(c *Context) error {
		return c.SendString("Welcome to the home page!")
	})
	router.Handle("GET", "/health", nil, HealthCheck())
	router.Handle("GET", "/static/*filepath", nil, func(c *Context) error {
		fp := c.Param("filepath")
		http.ServeFile(c.Writer, c.Request, "./static/"+fp)
		return nil
	})
	router.Handle("GET", "/users/{id}", nil, func(c *Context) error {
		return c.JSON(200, map[string]string{"user": c.Param("id")})
	})
	router.Handle("GET", "/items/{id:\\d+}", nil, func(c *Context) error {
		return c.JSON(200, map[string]string{"item": c.Param("id")})
	})
	router.Handle("GET", "/posts/{slug?}", nil, func(c *Context) error {
		slug := c.Param("slug")
		if slug == "" {
			return c.JSON(200, map[string]string{"posts": "all"})
		} else {
			return c.JSON(200, map[string]string{"post": slug})
		}
	})
	api := router.Group("/api", JWTAuth([]byte("secret")))
	v1 := api.router.Group("/api/v1")
	v1.Handle("GET", "/users", nil, func(c *Context) error {
		return c.JSON(200, []string{"user1", "user2"})
	})
	v1.Handle("POST", "/upload", nil, func(c *Context) error {
		file, err := c.FileForm("file")
		if err != nil {
			c.Writer.WriteHeader(400)
			return err
		}
		out, err := os.Create("/tmp/" + file.Filename)
		if err != nil {
			c.Writer.WriteHeader(500)
			return err
		}
		defer out.Close()
		in, err := file.Open()
		if err != nil {
			c.Writer.WriteHeader(500)
			return err
		}
		defer in.Close()
		io.Copy(out, in)
		c.Writer.WriteHeader(201)
		return nil
	})
	router.Handle("GET", "/redirect", nil, func(c *Context) error {
		if c.Request.URL.Path == "/" {
			return c.JSON(200, map[string]string{"message": "Already at home"})
		}
		http.Redirect(c.Writer, c.Request, "/", http.StatusFound)
		return nil
	})
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s", err)
		}
	}()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}
