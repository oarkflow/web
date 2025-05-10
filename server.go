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

type HandlerFunc func(*Context) error

type Context struct {
	Writer   http.ResponseWriter
	Request  *http.Request
	Params   map[string]string
	index    int
	handlers []HandlerFunc
}

func (c *Context) Next() error {
	c.index++
	for c.index < len(c.handlers) {
		if err := c.handlers[c.index](c); err != nil {
			return err
		}
		c.index++
	}
	return nil
}

func (c *Context) Abort() {
	c.index = len(c.handlers)
}

func (c *Context) JSON(status int, v interface{}) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(status)
	json.NewEncoder(c.Writer).Encode(v)
}

func (c *Context) XML(status int, v interface{}) {
	c.Writer.Header().Set("Content-Type", "application/xml")
	c.Writer.WriteHeader(status)
	xml.NewEncoder(c.Writer).Encode(v)
}

func (c *Context) BindJSON(v interface{}) error {
	if ct := c.Request.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		return errors.New("invalid content-type")
	}
	return json.NewDecoder(c.Request.Body).Decode(v)
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

func (c *Context) SetCookie(cookie *http.Cookie) {
	http.SetCookie(c.Writer, cookie)
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
	regex     *regexp.Regexp
	optional  bool
	children  []*node
	handlers  map[string][]HandlerFunc
}

func NewRouter() *Router {
	return &Router{
		trees:            make(map[string]*node),
		notFound:         DefaultNotFoundHandler,
		methodNotAllowed: DefaultMethodNotAllowedHandler,
		errorHandler:     DefaultErrorHandler,
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
		var isWild bool
		var paramName string
		var regex *regexp.Regexp
		var optional bool
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
				regex:     regex,
				optional:  optional,
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
			if c.regex != nil {
				if !c.regex.MatchString(seg) {
					continue
				}
			}
			return c
		}
		if c.segment == seg {
			return c
		}
	}
	return nil
}

func (r *Router) Handle(method, pattern string, handlers ...HandlerFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(handlers) == 0 {
		panic("no handler provided")
	}
	handler := handlers[len(handlers)-1]
	mws := handlers[:len(handlers)-1]
	r.addRoute(method, pattern, mws, handler)
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	method := req.Method
	p := strings.Trim(req.URL.Path, "/")
	segs := []string{}
	if p != "" {
		segs = strings.Split(p, "/")
	}
	if root, ok := r.trees[method]; ok {
		params := make(map[string]string)
		if h, ok := r.search(root, segs, params, method); ok {
			c := &Context{
				Writer:   w,
				Request:  req,
				Params:   params,
				handlers: h,
				index:    -1,
			}
			defer func() {
				if rec := recover(); rec != nil {
					w.WriteHeader(500)
					fmt.Fprintf(w, "panic: %v", rec)
				}
			}()
			if err := c.Next(); err != nil {
				r.errorHandler(c, err)
			}
			return
		}
	}
	for m, root := range r.trees {
		if m == method {
			continue
		}
		if r.matchPattern(root, segs) {
			r.methodNotAllowed(&Context{Writer: w, Request: req})
			return
		}
	}
	r.notFound(&Context{Writer: w, Request: req})
}

func (r *Router) search(n *node, segs []string, params map[string]string, method string) ([]HandlerFunc, bool) {
	if len(segs) == 0 {
		if h, ok := n.handlers[method]; ok && len(n.handlers) > 0 {
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
			if h, ok := r.search(c, segs[1:], params, method); ok {
				return h, true
			}
			if c.optional {
				if h, ok := r.search(c, segs, params, method); ok {
					return h, true
				}
			}
		} else {
			if c.segment == segs[0] {
				if h, ok := r.search(c, segs[1:], params, method); ok {
					return h, true
				}
				if c.optional {
					if h, ok := r.search(c, segs, params, method); ok {
						return h, true
					}
				}
			}
		}
	}
	return nil, false
}

func (r *Router) matchPattern(n *node, segs []string) bool {
	if len(segs) == 0 {
		if len(n.handlers) > 0 {
			return true
		}
		for _, c := range n.children {
			if c.optional && r.matchPattern(c, segs) {
				return true
			}
		}
		return false
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
		} else {
			if c.segment == segs[0] {
				if r.matchPattern(c, segs[1:]) {
					return true
				}
				if c.optional && r.matchPattern(c, segs) {
					return true
				}
			}
		}
	}
	return false
}

func (r *Router) Group(prefix string, mws ...HandlerFunc) *Group {
	return &Group{prefix: prefix, mw: mws, router: r}
}

type Group struct {
	prefix string
	mw     []HandlerFunc
	router *Router
}

func (g *Group) Handle(method, pattern string, handlers ...HandlerFunc) {
	full := path.Join(g.prefix, pattern)
	all := append(g.mw, handlers...)
	g.router.Handle(method, full, all...)
}

func (g *Group) GET(pattern string, h ...HandlerFunc) {
	g.Handle("GET", pattern, h...)
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

func Logger() HandlerFunc {
	return func(c *Context) error {
		start := time.Now()
		err := c.Next()
		log.Printf("%s %s %d %s", c.Request.Method, c.Request.URL.Path, 200, time.Since(start))
		return err
	}
}

func Recovery() HandlerFunc {
	return func(c *Context) error {
		defer func() {
			if err := recover(); err != nil {
				c.Writer.WriteHeader(500)
				c.Writer.Write([]byte(fmt.Sprint(err)))
				c.Abort()
			}
		}()
		return c.Next()
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

func RateLimiter(rps int) HandlerFunc {
	ticker := time.NewTicker(time.Second / time.Duration(rps))
	return func(c *Context) error {
		<-ticker.C
		return c.Next()
	}
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

func HealthCheck() HandlerFunc {
	return func(c *Context) error {
		c.JSON(200, map[string]string{"status": "healthy"})
		return nil
	}
}

func main() {
	router := NewRouter()
	router.Use(Recovery(), Logger(), CORS(), SecurityHeaders(), Gzip())
	router.Handle("GET", "/", func(c *Context) error {
		c.JSON(200, map[string]string{"message": "Welcome"})
		return nil
	})
	router.Handle("GET", "/health", HealthCheck())
	router.Handle("GET", "/static/*filepath", func(c *Context) error {
		fp := c.Param("filepath")
		http.ServeFile(c.Writer, c.Request, "./static/"+fp)
		return nil
	})
	router.Handle("GET", "/users/{id}", func(c *Context) error {
		c.JSON(200, map[string]string{"user": c.Param("id")})
		return nil
	})
	router.Handle("GET", "/items/{id:\\d+}", func(c *Context) error {
		c.JSON(200, map[string]string{"item": c.Param("id")})
		return nil
	})
	router.Handle("GET", "/posts/{slug?}", func(c *Context) error {
		slug := c.Param("slug")
		if slug == "" {
			c.JSON(200, map[string]string{"posts": "all"})
		} else {
			c.JSON(200, map[string]string{"post": slug})
		}
		return nil
	})
	admin := router.Group("/admin", JWTAuth([]byte("secret")))
	admin.Handle("GET", "/dashboard", func(c *Context) error {
		c.JSON(200, map[string]string{"dashboard": "admin"})
		return nil
	})
	api := router.Group("/api/v1")
	api.Handle("GET", "/users", func(c *Context) error {
		c.JSON(200, []string{"user1", "user2"})
		return nil
	})
	api.Handle("POST", "/upload", func(c *Context) error {
		file, err := c.FileForm("file")
		if err != nil {
			c.Writer.WriteHeader(400)
			return err
		}
		out, err := os.Create("/tmp/" + file.Filename)
		if err != nil {
			return err
		}
		defer out.Close()
		in, err := file.Open()
		if err != nil {
			return err
		}
		defer in.Close()
		io.Copy(out, in)
		c.Writer.WriteHeader(201)
		return nil
	})
	router.Handle("GET", "/redirect", func(c *Context) error {
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
