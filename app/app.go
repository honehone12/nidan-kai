package app

import (
	"errors"
	"net/http"
	"nidan-kai/ent"
	"nidan-kai/ent/user"
	"nidan-kai/keystore/oskeyring"
	"nidan-kai/loginmethod"
	"nidan-kai/nidankai"
	"nidan-kai/secretstore/encryptedb"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"

	_ "github.com/go-sql-driver/mysql"
)

type App struct {
	ent       *ent.Client
	nidanKai  *nidankai.NidanKai
	validator *validator.Validate
}

type SetUpRequest struct {
	Email string `form:"email" validate:"required,email,max=256"`
}

func NewApp() (*App, error) {
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

	secretStore, err := encryptedb.NewEncrypteDB(ent, oskeyring.OsKeyring{})
	if err != nil {
		return nil, err
	}

	nidanKai, err := nidankai.NewNidankai(secretStore)
	if err != nil {
		return nil, err
	}

	validator := validator.New()

	return &App{
		ent,
		nidanKai,
		validator,
	}, nil
}

func (a *App) bind(ctx echo.Context, target any) error {
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

	u, err := a.ent.User.Query().
		Select(
			user.FieldID,
			user.FieldLoginMethod,
		).
		Where(
			user.Email(form.Email),
			user.DeletedAtIsNil(),
		).
		Only(ctx.Request().Context())
	if ent.IsNotFound(err) {
		ctx.Logger().Warn("could not find user")
		return echo.ErrBadRequest
	} else if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	if u.LoginMethod != loginmethod.LOGIN_METHOD_MFA_QR {
		ctx.Logger().Warn("wrong login method")
		return echo.ErrBadRequest
	}

	qr, err := a.nidanKai.SetUp(
		ctx.Request().Context(),
		nidankai.SetUpParams{
			Issuer:    "NidanKai",
			UserId:    u.ID,
			UserEmail: form.Email,
		},
	)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	return ctx.String(http.StatusOK, qr)
}

func (a *App) Verify(ctx echo.Context) error {

	return echo.ErrNotImplemented
}

func (a *App) Close() error {
	return a.nidanKai.Close()
}
