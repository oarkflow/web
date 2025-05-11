package main

import (
	web "github.com/oarkflow/web/server"
)

func main() {
	session := web.NewSessionManager("SESSIONID")
	s := web.NewServer(web.WithAddress(":8080"), web.WithSession(session))

	// Basic routes examples:
	s.Get("/", func(ctx web.Context) error {
		return ctx.SendString("Hello from GET")
	})
	s.Post("/submit", func(ctx web.Context) error {
		return ctx.SendString("Submitted via POST")
	})
	s.Put("/update", func(ctx web.Context) error {
		return ctx.SendString("Resource updated via PUT")
	})
	s.Delete("/remove", func(ctx web.Context) error {
		return ctx.SendString("Resource deleted via DELETE")
	})
	s.Patch("/modify", func(ctx web.Context) error {
		return ctx.SendString("Resource modified via PATCH")
	})
	s.Options("/options", func(ctx web.Context) error {
		return ctx.SendString("OPTIONS response")
	})
	s.Head("/head", func(ctx web.Context) error {
		// HEAD usually sends headers only.
		return nil
	})
	s.Connect("/connect", func(ctx web.Context) error {
		return ctx.SendString("CONNECT response")
	})
	s.Trace("/trace", func(ctx web.Context) error {
		return ctx.SendString("TRACE response")
	})

	s.Get("/add-route", func(ctx web.Context) error {
		s.AddRoute("GET", "/dynamic", func(ctx web.Context) error {
			return ctx.SendString("Dynamic route added")
		})
		return ctx.SendString("Dynamic route added")
	})

	s.Get("/update-route", func(ctx web.Context) error {
		s.UpdateRoute("GET", "/dynamic", func(ctx web.Context) error {
			return ctx.SendString("Dynamic route updated")
		})
		return ctx.SendString("Dynamic route updated")
	})

	s.Get("/remove-route", func(ctx web.Context) error {
		s.RemoveRoute("GET", "/dynamic")
		return ctx.SendString("Dynamic route removed")
	})

	// Group routing example:
	api := s.Group("/api")
	api.Add("GET", "/users", func(ctx web.Context) error {
		return ctx.SendString("API: List of users")
	})
	api.Add("POST", "/users", func(ctx web.Context) error {
		return ctx.SendString("API: Create user")
	})
	// You can also remove or update routes inside a group:
	api.Update("GET", "/users", func(ctx web.Context) error {
		return ctx.SendString("API: Updated users list")
	})
	api.Remove("POST", "/users")

	// Static route
	s.Get("/blog/:post", func(ctx web.Context) error {
		return ctx.SendString(ctx.Request().Param("post"))
	})

	// Wildcard route
	s.Get("/images/*file", func(ctx web.Context) error {
		return ctx.SendString(ctx.Request().Param("file"))
	})

	// Session example: Login route that sets a session variable.
	s.Get("/login", func(ctx web.Context) error {
		sess := ctx.Session()
		if sess == nil {
			return ctx.SendString("Session not available")
		}
		// mark user as authenticated in session
		sess.Set("authenticated", true)
		return ctx.SendString("Logged in successfully!")
	})

	// Protected route: Only accessible if the user is "authenticated" in session.
	s.Get("/protected", func(ctx web.Context) error {
		sess := ctx.Session()
		if sess == nil {
			ctx.Status(401)
			return ctx.SendString("Unauthorized: Please login first")
		}
		if _, ok := sess.Get("authenticated"); !ok {
			ctx.Status(401)
			return ctx.SendString("Unauthorized: Please login first")
		}
		return ctx.SendString("Welcome to the protected route!")
	})

	s.Run()
}
