package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"nidan-kai/binid"
	"nidan-kai/ent"
	"nidan-kai/ent/enttest"
	"nidan-kai/ent/user"
	"nidan-kai/nidankai"
	"nidan-kai/secretstore"
	"nidan-kai/secretstore/encryptedb"
	"strings"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

// mockKeystore is a mock implementation of the keystore.Keystore interface for testing.
type mockKeystore struct {
	key     []byte
	initErr error
	getErr  error
}

func (m *mockKeystore) Init() error {
	return m.initErr
}

func (m *mockKeystore) GetKey() ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.key, nil
}

// setupAppTest initializes a full application stack with in-memory/mocked dependencies.
func setupAppTest(t *testing.T) (*App, *ent.Client, secretstore.SecretStore) {
	t.Helper()

	// 1. In-memory DB
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })

	// 2. Mock Keystore
	key := make([]byte, chacha20poly1305.KeySize)
	mockKS := &mockKeystore{key: key}

	// 3. Real SecretStore with mock dependencies
	secretStore, err := encryptedb.NewEncrypteDB(client.MfaQr, mockKS)
	require.NoError(t, err)

	// 4. Real NidanKai with real SecretStore
	nidanKaiService, err := nidankai.NewNidankai(secretStore)
	require.NoError(t, err)

	// 5. App instance with all test components
	app := &App{
		name:      "TestApp",
		ent:       client,
		nidanKai:  nidanKaiService,
		validator: validator.New(),
	}

	return app, client, secretStore
}

func TestApp_SetUp(t *testing.T) {
	app, client, _ := setupAppTest(t)
	ctx := context.Background()

	// Create a user to test with
	userID, _ := binid.NewRandom()
	u, err := client.User.Create().
		SetID(userID).
		SetName("test user").
		SetEmail("test@example.com").
		Save(ctx)
	require.NoError(t, err)

	t.Run("should set up MFA successfully and update login method", func(t *testing.T) {
		e := echo.New()
		form := url.Values{}
		form.Set("email", "test@example.com")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := app.SetUp(c)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, strings.HasPrefix(rec.Body.String(), "data:image/png;base64,"))

		// Verify user's login method was updated
		updatedUser, err := client.User.Get(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, user.LoginMethodMfaQr, updatedUser.LoginMethod)
	})

	t.Run("should return bad request for invalid form", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("email=not-an-email"))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := app.SetUp(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("should return bad request for non-existent user", func(t *testing.T) {
		e := echo.New()
		form := url.Values{}
		form.Set("email", "not-found@example.com")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := app.SetUp(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})
}

func TestApp_Verify(t *testing.T) {
	app, client, secretStore := setupAppTest(t)
	ctx := context.Background()

	// 1. Create a user with mfa-qr login method
	userID, _ := binid.NewRandom()
	_, err := client.User.Create().
		SetID(userID).
		SetName("verify user").
		SetEmail("verify@example.com").
		SetLoginMethod(user.LoginMethodMfaQr).
		Save(ctx)
	require.NoError(t, err)

	// 2. Manually set up a secret for them by calling the real SetUp logic
	params := nidankai.SetUpParams{
		Issuer: app.name,
		UserId: userID,
		Email:  "verify@example.com",
	}
	_, err = app.nidanKai.SetUp(ctx, params)
	require.NoError(t, err)

	t.Run("should verify successfully with correct code", func(t *testing.T) {
		// 3. Get the secret from the store to calculate the correct code
		secret, err := secretStore.GetSecret(ctx, userID)
		require.NoError(t, err)

		// 4. Calculate code using local copy of totp logic
		now := time.Now().Unix()
		code, err := nidankai.Totp(secret, now, nidankai.QR_MFA_PERIOD)
		require.NoError(t, err)

		e := echo.New()
		form := url.Values{}
		form.Set("email", "verify@example.com")
		form.Set("code", fmt.Sprintf("%06d", code))
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = app.Verify(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("should fail for incorrect code", func(t *testing.T) {
		e := echo.New()
		form := url.Values{}
		form.Set("email", "verify@example.com")
		form.Set("code", "000000")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := app.Verify(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("should fail for user with wrong login method", func(t *testing.T) {
		// Create a user with 'password' login method
		pwUserID, _ := binid.NewRandom()
		pwUser, _ := client.User.Create().
			SetID(pwUserID).
			SetName("pw user").
			SetEmail("pw@example.com").
			SetLoginMethod(user.LoginMethodPassword).
			Save(ctx)

		e := echo.New()
		form := url.Values{}
		form.Set("email", pwUser.Email)
		form.Set("code", "123456")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := app.Verify(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})
}
