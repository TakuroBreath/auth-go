# Auth Service

Простой сервис аутентификации на Go с поддержкой JWT токенов и механизма обновления.

## Что умеет

- Выдача пары токенов (access + refresh) по ID пользователя
- Обновление токенов через refresh token
- Отслеживание подозрительной активности по IP
- Уведомления на почту при смене IP

## Технологии

- Go
- PostgreSQL
- JWT

## Установка и запуск

1. Клонируем репозиторий
2. Создаем `.env` файл:
```env
JWT_SECRET="your-secret"
DB_HOST="localhost"
DB_PORT="5432"
DB_USER="postgres"
DB_PASSWORD="your-password"
DB_NAME="auth_db"
DB_SSLMODE="disable"
SERVER_PORT="8080"
ACCESS_TOKEN_TTL="15m"
REFRESH_TOKEN_TTL="24h"
```

3. Запускаем PostgreSQL и создаем базу:
```bash
createdb auth_db
psql -d auth_db -f internal/storage/postgresql/schema.sql
```

4. Запускаем сервис:
```bash
go run cmd/auth-go/main.go
```

## API

### Получение токенов
```bash
curl -X POST http://localhost:8080/auth/tokens \
  -H "Content-Type: application/json" \
  -d '{"user_id": "123e4567-e89b-12d3-a456-426614174000"}'
```

### Обновление токенов
```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "ваш-рефреш-токен"}'
```

## Безопасность

- Access token: JWT с SHA512
- Refresh token: хранится в виде bcrypt хеша
- Проверка IP при обновлении токенов
