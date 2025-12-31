package main

import (
	"net/url"
	"nidan-kai/app"

	echo4 "github.com/labstack/echo/v4"
	echo4middleware "github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func run() {
	echo := echo4.New()
	echo.Use(echo4middleware.RequestLogger())
	echo.Logger.SetLevel(log.INFO)

	uiUrl, err := url.Parse("http://localhost:3000")
	if err != nil {
		echo.Logger.Fatal(err)
	}
	balancer := echo4middleware.NewRoundRobinBalancer(
		[]*echo4middleware.ProxyTarget{{
			Name: "ui",
			URL:  uiUrl,
		}})

	app, err := app.NewApp()
	if err != nil {
		echo.Logger.Fatal(err)
	}
	defer app.Close()

	echo.POST("/api/mfa/qr/setup", app.SetUp)
	echo.POST("/api/mfa/qr/verify", app.Verify)

	echo.Group("/*", echo4middleware.Proxy(balancer))

	if err := echo.Start("localhost:8081"); err != nil {
		echo.Logger.Fatal(err)
	}
}
