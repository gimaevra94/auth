package tools

import (
	"os"
	"testing"
	"time"

	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRefreshToken(t *testing.T) {
	originalSecret := os.Getenv("JWT_SECRET")
	testSecret := "test-secret-key-for-testing"
	os.Setenv("JWT_SECRET", testSecret)
	defer func() {
		if originalSecret != "" {
			os.Setenv("JWT_SECRET", originalSecret)
		} else {
			os.Unsetenv("JWT_SECRET")
		}
	}()

	tests := []struct {
		name            string
		refreshTokenExp int
		rememberMe      bool
		wantErr         bool
		description     string
	}{
		{
			name:            "RememberMe_true_custom_expiration",
			refreshTokenExp: 7200, 
			rememberMe:      true,
			wantErr:         false,
			description:     "Генерация токена с флагом rememberMe=true и кастомным временем жизни",
		},
		{
			name:            "RememberMe_false_default_24h",
			refreshTokenExp: 3600, 
			rememberMe:      false,
			wantErr:         false,
			description:     "Генерация токена с флагом rememberMe=false (должен использовать 24 часа по умолчанию)",
		},
		{
			name:            "RememberMe_true_zero_expiration",
			refreshTokenExp: 0,
			rememberMe:      true,
			wantErr:         false,
			description:     "Генерация токена с нулевым временем жизни (немедленный истек)",
		},
		{
			name:            "RememberMe_false_large_expiration",
			refreshTokenExp: 999999, 
			rememberMe:      false,
			wantErr:         false,
			description:     "Генерация токена с большим значением времени жизни, но rememberMe=false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateRefreshToken(tt.refreshTokenExp, tt.rememberMe)

			if tt.wantErr {
				assert.Error(t, err, tt.description)
				assert.Empty(t, got, tt.description)
				return
			}

			require.NoError(t, err, tt.description)
			assert.NotEmpty(t, got, tt.description)

			token, err := jwt.ParseWithClaims(got, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(testSecret), nil
			})

			require.NoError(t, err, tt.description)
			require.True(t, token.Valid, tt.description)

			claims, ok := token.Claims.(*jwt.StandardClaims)
			require.True(t, ok, tt.description)

			expectedExpiresAt := time.Now().Unix()
			if !tt.rememberMe {
				expectedExpiresAt += 24 * 60 * 60 // 24 часа
			} else {
				expectedExpiresAt += int64(tt.refreshTokenExp)
			}

			assert.InDelta(t, expectedExpiresAt, claims.ExpiresAt, 1, tt.description)
			assert.NotZero(t, claims.IssuedAt, tt.description)
		})
	}
}

func TestGenerateRefreshToken_MissingJWTSecret(t *testing.T) {
	originalSecret := os.Getenv("JWT_SECRET")
	os.Unsetenv("JWT_SECRET")
	defer func() {
		if originalSecret != "" {
			os.Setenv("JWT_SECRET", originalSecret)
		}
	}()

	_, err := GenerateRefreshToken(3600, true)
	assert.Error(t, err, "Должна быть ошибка при отсутствующем JWT_SECRET")
}

func TestGeneratePasswordResetLink(t *testing.T) {
	originalSecret := os.Getenv("JWT_SECRET")
	testSecret := "test-secret-key-for-password-reset"
	os.Setenv("JWT_SECRET", testSecret)
	defer func() {
		if originalSecret != "" {
			os.Setenv("JWT_SECRET", originalSecret)
		} else {
			os.Unsetenv("JWT_SECRET")
		}
	}()

	tests := []struct {
		name        string
		email       string
		baseURL     string
		wantErr     bool
		description string
	}{
		{
			name:        "Valid_email_and_baseURL",
			email:       "test@example.com",
			baseURL:     "https://example.com/reset",
			wantErr:     false,
			description: "Генерация ссылки с валидными email и baseURL",
		},
		{
			name:        "Empty_email",
			email:       "",
			baseURL:     "https://example.com/reset",
			wantErr:     false, 
			description: "Генерация ссылки с пустым email",
		},
		{
			name:        "Empty_baseURL",
			email:       "test@example.com",
			baseURL:     "",
			wantErr:     false, 
			description: "Генерация ссылки с пустым baseURL",
		},
		{
			name:        "BaseURL_with_existing_params",
			email:       "test@example.com",
			baseURL:     "https://example.com/reset?param=value",
			wantErr:     false,
			description: "Генерация ссылки с baseURL, содержащим существующие параметры",
		},
		{
			name:        "Special_characters_in_email",
			email:       "test+tag@example.co.uk",
			baseURL:     "https://example.com/reset",
			wantErr:     false,
			description: "Генерация ссылки с email, содержащим специальные символы",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GeneratePasswordResetLink(tt.email, tt.baseURL)

			if tt.wantErr {
				assert.Error(t, err, tt.description)
				assert.Empty(t, got, tt.description)
				return
			}

			require.NoError(t, err, tt.description)
			assert.NotEmpty(t, got, tt.description)

			assert.Contains(t, got, tt.baseURL, tt.description)
			assert.Contains(t, got, "?token=", tt.description)

			tokenString := got[len(tt.baseURL)+7:] // +7 для "?token="

			token, err := jwt.ParseWithClaims(tokenString, &structs.PasswordResetTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(testSecret), nil
			})

			require.NoError(t, err, tt.description)
			require.True(t, token.Valid, tt.description)

			claims, ok := token.Claims.(*structs.PasswordResetTokenClaims)
			require.True(t, ok, tt.description)

			assert.Equal(t, tt.email, claims.Email, tt.description)

			expectedExpiresAt := time.Now().Add(15 * time.Minute).Unix()
			assert.InDelta(t, expectedExpiresAt, claims.ExpiresAt, 1, tt.description)
			assert.NotZero(t, claims.IssuedAt, tt.description)
		})
	}
}

func TestGeneratePasswordResetLink_MissingJWTSecret(t *testing.T) {
	originalSecret := os.Getenv("JWT_SECRET")
	os.Unsetenv("JWT_SECRET")
	defer func() {
		if originalSecret != "" {
			os.Setenv("JWT_SECRET", originalSecret)
		}
	}()

	_, err := GeneratePasswordResetLink("test@example.com", "https://example.com/reset")
	assert.Error(t, err, "Должна быть ошибка при отсутствующем JWT_SECRET")
}

func TestGenerateRefreshToken_TokenExpiration(t *testing.T) {
	originalSecret := os.Getenv("JWT_SECRET")
	testSecret := "test-secret-key"
	os.Setenv("JWT_SECRET", testSecret)
	defer func() {
		if originalSecret != "" {
			os.Setenv("JWT_SECRET", originalSecret)
		} else {
			os.Unsetenv("JWT_SECRET")
		}
	}()

	shortExp := 1 
	token, err := GenerateRefreshToken(shortExp, true)
	require.NoError(t, err)

	parsedToken, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(testSecret), nil
	})
	require.NoError(t, err)
	require.True(t, parsedToken.Valid)

	time.Sleep(2 * time.Second)

	parsedToken, err = jwt.ParseWithClaims(token, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(testSecret), nil
	})
	assert.Error(t, err, "Токен должен быть недействительным после истечения срока")
	assert.False(t, parsedToken.Valid)
}

func TestGeneratePasswordResetLink_TokenExpiration(t *testing.T) {
	originalSecret := os.Getenv("JWT_SECRET")
	testSecret := "test-secret-key"
	os.Setenv("JWT_SECRET", testSecret)
	defer func() {
		if originalSecret != "" {
			os.Setenv("JWT_SECRET", originalSecret)
		} else {
			os.Unsetenv("JWT_SECRET")
		}
	}()

	link, err := GeneratePasswordResetLink("test@example.com", "https://example.com/reset")
	require.NoError(t, err)

	tokenString := link[len("https://example.com/reset")+7:]

	parsedToken, err := jwt.ParseWithClaims(tokenString, &structs.PasswordResetTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(testSecret), nil
	})
	require.NoError(t, err)
	require.True(t, parsedToken.Valid)

	claims := parsedToken.Claims.(*structs.PasswordResetTokenClaims)
	expiresIn := claims.ExpiresAt - time.Now().Unix()
	assert.Greater(t, expiresIn, int64(14*60), "Токен должен жить около 15 минут")
	assert.Less(t, expiresIn, int64(16*60), "Токен не должен жить дольше 16 минут")
}

func BenchmarkGenerateRefreshToken(b *testing.B) {
	originalSecret := os.Getenv("JWT_SECRET")
	os.Setenv("JWT_SECRET", "benchmark-secret-key")
	defer func() {
		if originalSecret != "" {
			os.Setenv("JWT_SECRET", originalSecret)
		} else {
			os.Unsetenv("JWT_SECRET")
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateRefreshToken(3600, true)
	}
}

func BenchmarkGeneratePasswordResetLink(b *testing.B) {
	originalSecret := os.Getenv("JWT_SECRET")
	os.Setenv("JWT_SECRET", "benchmark-secret-key")
	defer func() {
		if originalSecret != "" {
			os.Setenv("JWT_SECRET", originalSecret)
		} else {
			os.Unsetenv("JWT_SECRET")
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GeneratePasswordResetLink("test@example.com", "https://example.com/reset")
	}
}
