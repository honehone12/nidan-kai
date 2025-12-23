package nidankai

import (
	echo4 "github.com/labstack/echo/v4"
	echo4middleware "github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func Run() {
	echo := echo4.New()
	echo.Use(echo4middleware.RequestLogger())
	echo.Logger.SetLevel(log.INFO)
	echo.Logger.SetPrefix("MOKNITO")
	echo.HTTPErrorHandler = func(err error, ctx echo4.Context) {
		ctx.Logger().Error(err)
		echo.DefaultHTTPErrorHandler(err, ctx)
	}

	if err := echo.Start("localhost:8081"); err != nil {
		echo.Logger.Fatal(err)
	}
}
