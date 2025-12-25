package app

import (
	echo4 "github.com/labstack/echo/v4"
	echo4middleware "github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func Run() {
	echo := echo4.New()
	echo.Use(echo4middleware.RequestLogger())
	echo.Logger.SetLevel(log.INFO)

	echo.Use(echo4middleware.CORSWithConfig(echo4middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:3000"},
	}))

	app, err := NewApp()
	if err != nil {
		echo.Logger.Fatal(err)
	}
	defer app.Close()

	echo.POST("/api/mfa/qr/setup", app.SetUp)
	echo.POST("/api/mfa/qr/verify", app.Verify)

	if err := echo.Start("localhost:8081"); err != nil {
		echo.Logger.Fatal(err)
	}
}
