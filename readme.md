# Auth Service

Go-сервис аутентификации и управления сессиями с веб-интерфейсом.

Реализованы:
- регистрация с подтверждением по email-коду;
- вход по логину и паролю;
- вход через Yandex OAuth;
- восстановление пароля по email-ссылке;
- выдача `temporaryId` (cookie) и `refresh token`;
- уведомления о входе с нового устройства и о подозрительной активности.

## Что внутри

- `app/` - исходный код сервиса на Go (HTTP-роуты, auth-логика, доступ к данным, шаблоны, тесты).
- `public/auth-db.sql` - схема MySQL.
- `public/.env` - файл с конфигурацией приложения (не хранится в Git).
- `Docker/` - `docker-compose.yml` и Dockerfile для приложения и БД.
- `certs/` - TLS-сертификаты для приложения и MySQL.

## Стек

- Go 1.25+
- HTTP router: `chi`
- БД: MySQL
- Сессии: `gorilla/sessions`
- JWT: `golang-jwt/jwt`
- SMTP-отправка email (Yandex SMTP)
- Docker / Docker Compose
- TLS для `app` и MySQL

## Основные маршруты

- `GET /sign-up` - страница регистрации
- `POST /check-in-db-and-validate-sign-up-user-input` - валидация данных регистрации
- `GET /sign-in` - страница входа
- `POST /check-in-db-and-validate-sign-in-user-input` - вход по логину/паролю
- `GET /yauth` - старт Yandex OAuth
- `GET /ya_callback` - callback Yandex OAuth
- `GET /generate-password-reset-link` - страница запроса сброса пароля
- `POST /generate-password-reset-link` - отправка ссылки для сброса
- `POST /set-new-password` - установка нового пароля
- `GET /home` - защищенная домашняя страница
- `GET /logout` - выход

## Переменные окружения

Приложение ожидает следующие переменные:

- `CAPTCHA_STORE_SESSION_SECRET_KEY`
- `LOGIN_STORE_SESSION_AUTH_KEY`
- `LOGIN_STORE_SESSION_ENCRYPTION_KEY`
- `JWT_SECRET`
- `DB_PASSWORD`
- `SERVER_EMAIL`
- `SERVER_EMAIL_PASSWORD`
- `GOOGLE_CAPTCHA_SECRET`
- `clientId` (Yandex OAuth Client ID)
- `clientSecret` (Yandex OAuth Client Secret)
- `DB_SSL_CA`
- `DB_SSL_CERT`
- `DB_SSL_KEY`

В текущей Docker-конфигурации:
- `DB_PASSWORD` также передается как docker secret (`DB_PASSWORD_FILE`);
- файл `public/.env` монтируется в контейнер как `/app/.env`.

## Быстрый старт (рекомендуется, через Docker Compose)

1. Подготовьте файл `public/.env` с переменными из раздела выше.
2. Убедитесь, что сертификаты присутствуют:
   - `certs/app_cert/app-cert.pem`
   - `certs/app_cert/app-key.pem`
   - `certs/app_cert/ca.pem`
   - `certs/db_cert/ca.pem`
   - `certs/db_cert/db-cert.pem`
   - `certs/db_cert/db-key.pem`
3. Импортируйте схему БД из `public/auth-db.sql` (если БД запускается с чистого состояния).
4. Перед запуском экспортируйте `DB_PASSWORD` в окружение хоста (используется в `docker-compose.yml` как secret).
5. Запустите сервисы:

```bash
docker compose -f Docker/docker-compose.yml up -d
```

После запуска приложение доступно по `https://localhost` (порт `443`).

## Тестирование

Запуск unit-тестов:

```bash
cd app
go test ./...
```

## Безопасность и ограничения

- Приложение использует TLS и для HTTP-сервера, и для соединения с MySQL.
- В БД используется стратегия "soft delete" через поле `cancelled`.
- Схема БД в проекте без PK/FK-ограничений (это осознанное текущее решение).
