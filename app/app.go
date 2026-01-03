package app

import (
	"errors"
	"net/http"
	"nidan-kai/ent"
	"nidan-kai/ent/user"
	"nidan-kai/keystore/oskeyring"
	"nidan-kai/nidankai"
	"nidan-kai/secret"
	"nidan-kai/secretstore"
	"nidan-kai/secretstore/encryptedb"
	"strings"

	"os"
	"strconv"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"

	_ "github.com/go-sql-driver/mysql"
)

type App struct {
	appName string

	ent         *ent.Client
	validator   *validator.Validate
	secretStore secretstore.SecretStore
}

type SetUpRequest struct {
	Email string `form:"email" validate:"required,email,max=256"`
}

type VerifyRequest struct {
	Email string `form:"email" validate:"required,email,max=256"`
	Code  string `form:"code" validate:"required,number,len=6"`
}

func NewApp() (*App, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		return nil, errors.New("could not find env for mysql uri")
	}

	ent, err := ent.Open(
		"mysql",
		mysqlUri,
		ent.Debug(),
	)
	if err != nil {
		return nil, err
	}

	secretStore, err := encryptedb.NewEncrypteDB(ent.MfaQr, oskeyring.OsKeyring{})
	if err != nil {
		return nil, err
	}

	appName := "NidanKai"
	validator := validator.New()

	return &App{
		appName,
		ent,
		validator,
		secretStore,
	}, nil
}

func (a *App) bind(ctx echo.Context, target any) error {
	raw, _, _ := strings.Cut(ctx.Request().Header.Get(echo.HeaderContentType), ";")
	contentType := strings.TrimSpace(raw)
	if contentType != echo.MIMEApplicationForm {
		return errors.New("unexpected mime type")
	}

	if err := ctx.Bind(target); err != nil {
		return err
	}

	if err := a.validator.Struct(target); err != nil {
		return err
	}

	return nil
}

func (a *App) SetUp(ctx echo.Context) error {
	form := SetUpRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	c := ctx.Request().Context()
	u, err := a.ent.User.Query().
		Select(
			user.FieldID,
			user.FieldLoginMethod,
		).
		Where(
			user.Email(form.Email),
			user.DeletedAtIsNil(),
		).
		Only(c)
	if ent.IsNotFound(err) {
		ctx.Logger().Warn("could not find user")
		return echo.ErrBadRequest
	} else if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	if u.LoginMethod != user.LoginMethodMfaQr {
		err := a.ent.User.Update().
			Where(user.ID(u.ID)).
			SetLoginMethod(user.LoginMethodMfaQr).
			Exec(c)
		if err != nil {
			ctx.Logger().Error(err)
			return echo.ErrInternalServerError
		}
	}

	sec, err := secret.GenerateSecret()
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	if err := a.secretStore.SetSecret(c, u.ID, sec); err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	qr, err := nidankai.SetUp(a.appName, form.Email, sec)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	return ctx.String(http.StatusOK, qr)
}

func (a *App) Verify(ctx echo.Context) error {
	form := VerifyRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	code, err := strconv.Atoi(form.Code)
	if err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	c := ctx.Request().Context()
	u, err := a.ent.User.Query().
		Select(
			user.FieldID,
			user.FieldLoginMethod,
		).
		Where(
			user.Email(form.Email),
			user.DeletedAtIsNil(),
		).
		Only(c)
	if ent.IsNotFound(err) {
		ctx.Logger().Warn("could not find user")
		return echo.ErrBadRequest
	} else if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	if u.LoginMethod != user.LoginMethodMfaQr {
		ctx.Logger().Warn("wrong login method")
		return echo.ErrBadRequest
	}

	sec, err := a.secretStore.GetSecret(c, u.ID)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	ok, err := nidankai.Verify(code, sec)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}
	if !ok {
		ctx.Logger().Warn("invalid code")
		return echo.ErrBadRequest
	}

	return ctx.NoContent(http.StatusOK)
}

func (a *App) Close() error {
	return a.ent.Close()
}
