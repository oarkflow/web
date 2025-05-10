package main

import (
	"github.com/oarkflow/server/web"
)

func main() {
	s := web.NewServer()
	// Static route
	s.Get("/", func(ctx web.Context) error {
		return ctx.SendString("Hello")
	})

	// Parameter route
	s.Get("/blog/:post", func(ctx web.Context) error {
		return ctx.SendString(ctx.Request().Param("post"))
	})

	// Wildcard route
	s.Get("/images/*file", func(ctx web.Context) error {
		return ctx.SendString(ctx.Request().Param("file"))
	})
	s.Run(":8080")
}
