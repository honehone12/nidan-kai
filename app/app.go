package app

import (
	"errors"
	"net/http"
	"nidan-kai/binid"
	"nidan-kai/ent"
	"nidan-kai/ent/mfaqr"
	"nidan-kai/ent/user"
	"nidan-kai/keystore"
	"nidan-kai/keystore/envkey"
	"nidan-kai/nidankai"
	"nidan-kai/secret"
	"strings"

	"os"
	"strconv"

	"entgo.io/ent/dialect/sql"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"

	_ "github.com/go-sql-driver/mysql"
)

type App struct {
	appName string

	ent       *ent.Client
	validator *validator.Validate
	keystore  keystore.Keystore
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

	return &App{
		appName:   "NidanKai",
		ent:       ent,
		validator: validator.New(),
		keystore:  envkey.EnvKey{},
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

	sec, err := secret.GenerateEncryptedSecret(a.keystore)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	secId, err := binid.NewSequential()
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	err = a.ent.MfaQr.Create().
		SetID(secId).
		SetSecret(sec).
		SetUserID(u.ID).
		Exec(c)
	if err != nil {
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

	mfa, err := a.ent.MfaQr.Query().
		Select(
			mfaqr.FieldSecret,
		).
		Where(
			mfaqr.UserID(u.ID),
			mfaqr.DeletedAtIsNil(),
		).
		Order(sql.OrderByField(mfaqr.FieldCreatedAt, sql.OrderDesc()).ToFunc()).
		Limit(1).
		First(c)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	sec, err := secret.Decrypt(mfa.Secret, a.keystore)
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
