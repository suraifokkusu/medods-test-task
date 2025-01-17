# Сервис Аутентификации
Этот репозиторий содержит тестовое задание для компании MEDODS, сервис аутентификации, написанный на Go с использованием JWT и PostgreSQL.
## Особенности
- Генерация **Access** и **Refresh** токенов для пользователей.
- Использование **JWT** с алгоритмом **SHA512** для Access токенов.
- Хранение Refresh токенов в виде bcrypt-хэшей в базе данных PostgreSQL.
- Проверка изменения IP-адреса при обновлении токенов и отправка предупреждения на почту (моковые данные).
- Полностью контейнеризован для простого развертывания и тестирования через Docker.
## Используемые технологии
- Go
- PostgreSQL
- JWT (JSON Web Tokens)
- Docker
## Установка и запуск
### Клонирование репозитория
```bash
git clone https://github.com/suraifokkusu/medods-test-task.git
cd medods-test-task
```
### Запуск через Docker
1. Убедитесь, что у вас установлен Docker.
2. Выполните команду:
```bash
make build
```
3. Запустите приложение:
```bash
make up
```
### Запуск тестов
Для запуска тестов используйте команду:
```bash
make test
```
## Описание API
### 1. Генерация токенов
**Маршрут**: `/token`
**Метод**: `POST`
**Параметры**: `user_id` (GUID пользователя)
**Описание**: Генерирует пару токенов Access и Refresh.
Пример:
```bash
curl -X POST "http://localhost:8080/token?user_id=30aecc06-7661-445b-af3b-356ce8cdd822"
```
### 2. Обновление токенов
**Маршрут**: `/refresh`
**Метод**: `POST`
**Тело запроса**:
```json
{
  "access_token": "текущий access токен",
  "refresh_token": "текущий refresh токен"
}
```
**Описание**: Обновляет пару токенов Access и Refresh. Если IP-адрес изменился, отправляется предупреждение на почту.
Пример:
```bash
curl -X POST "http://localhost:8080/refresh" \
-H "Content-Type: application/json" \
-d '{
  "access_token": "ваш_access_token",
  "refresh_token": "ваш_refresh_token"
}'
```
## Логи
Для просмотра логов используйте команду:
```bash
make logs
```
## Очистка и пересборка
Для полной очистки проекта и пересборки:
```bash
make rebuild
```