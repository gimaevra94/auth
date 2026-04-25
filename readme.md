# Сервис аутентификации

Веб-приложение на Go для регистрации, входа и управления пользовательскими сессиями.

## 📋 Возможности

- **Регистрация по email**: подтверждение через одноразовый код
- **Вход по логину и паролю**: с выдачей `temporaryId` и `refresh token`
- **Yandex OAuth**: авторизация через Яндекс
- **Сброс пароля**: отправка ссылки на email и установка нового пароля
- **Защита от брутфорса**: reCAPTCHA после неудачных попыток
- **Уведомления безопасности**: письма о входе с нового устройства и подозрительной активности

## 🏗️ Архитектура проекта

```text
├── app/               # Основной Go-код (auth, data, captcha, templates, tests)
├── public/            # SQL-схема, статические файлы, .env (локально)
├── certs/             # TLS-сертификаты для app и MySQL
├── Docker/            # Dockerfile и docker-compose
└── .github/workflows/ # CI-пайплайн
```

## 🚀 Быстрый старт

### Требования
- Docker и Docker Compose
- Go 1.25+ (для локального запуска и тестов)
- SMTP-аккаунт для отправки писем (Yandex SMTP)

### Запуск через Docker Compose

1. Создайте файл `public/.env` и заполните переменные из раздела "Конфигурация".
2. Убедитесь, что доступны сертификаты:
   - `certs/app_cert/app-cert.pem`
   - `certs/app_cert/app-key.pem`
   - `certs/app_cert/ca.pem`
   - `certs/db_cert/ca.pem`
   - `certs/db_cert/db-cert.pem`
   - `certs/db_cert/db-key.pem`
3. Экспортируйте `DB_PASSWORD` в окружение хоста (используется как docker secret).
4. Запустите контейнеры:

```bash
docker compose -f Docker/docker-compose.yml up -d
```

Приложение будет доступно по адресу:
- **Веб-интерфейс**: https://localhost (порт 443)
- **MySQL**: localhost:3306

### Локальная разработка

1. **Запуск базы данных**:
```bash
docker compose -f Docker/docker-compose.yml up -d db
```

2. **Инициализация схемы БД** (однократно):
```bash
# импортируйте SQL из public/auth-db.sql в базу db
```

3. **Запуск приложения**:
```bash
cd app
go run .
```

## 🔧 Конфигурация

Приложение использует переменные окружения:

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

В Docker-сценарии `public/.env` монтируется в `/app/.env`, а `DB_PASSWORD` дополнительно передается через секрет `DB_PASSWORD_FILE`.

## 📦 Технологический стек

- **Backend**: Go 1.25, `chi`
- **База данных**: MySQL
- **Сессии**: `gorilla/sessions`
- **Токены**: `golang-jwt/jwt`
- **Почта**: SMTP (Yandex)
- **Контейнеризация**: Docker, Docker Compose
- **Безопасность**: TLS для приложения и MySQL

## 🔐 Аутентификация и сессии

- При успешном входе создаются `temporaryId` (cookie) и `refresh token`.
- Для хранения auth/captcha-состояния используются серверные сессии.
- При смене пароля активные токены и сессии для текущего `userAgent` отзываются.
- В БД используется soft delete через поле `cancelled`.

## 📝 Эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/` | Редирект на регистрацию |
| GET | `/sign-up` | Страница регистрации |
| POST | `/check-in-db-and-validate-sign-up-user-input` | Проверка данных регистрации |
| POST | `/code-validate` | Подтверждение кода из email |
| GET | `/sign-in` | Страница входа |
| POST | `/check-in-db-and-validate-sign-in-user-input` | Вход по логину/паролю |
| GET | `/yauth` | Начало Yandex OAuth |
| GET | `/ya_callback` | Callback Yandex OAuth |
| GET/POST | `/generate-password-reset-link` | Запрос ссылки сброса пароля |
| GET/POST | `/set-new-password` | Установка нового пароля |
| GET | `/home` | Защищенная страница пользователя |
| GET | `/logout` | Выход из системы |

## 🧪 Тестирование

```bash
cd app
go test ./...
```

## 📄 Примечания

- SQL-схема находится в `public/auth-db.sql`.
- В проекте не используются PK/FK-ограничения в таблицах (текущее архитектурное решение).
