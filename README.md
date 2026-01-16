# Cloud Storage

## Описание проекта

**Cloud Storage** — это веб-приложение для хранения и управления файлами с поддержкой авторизации пользователей.

## Основные возможности

* **Регистрация и авторизация** пользователей
* **Загрузка файлов** с сохранением метаданных
* **Управление файлами**: добавление, просмотр, редактирование, удаление, возможность поделиться файлами
* **Админ-панель** для управления пользователями
* **JWT-авторизация** с поддержкой refresh-токенов
* **CORS-поддержка** для работы с фронтендом

## Технологии

* **Django** 5.2.8
* **Django REST Framework**
* **Simple JWT** для аутентификации
* **PostgreSQL** для хранения данных
* **Python** 3.8+

### Требования

* Python 3.8+
* PostgreSQL
* pip

### Установка зависимостей
pip install -r requirements.txt

### Настройка
Создайте файл .env в корне проекта

Добавьте переменные окружения:
DEBUG=True/False
SECRET_KEY= 'Ваш секретный ключ приложения джанго'
DATABASE_URL=postgresql://user:password@localhost/dbname Ваша база данных
ALLOWED_HOSTS=localhost, Ваш хост
STATIC_URL=/static/
STATIC_ROOT=/path/to/your/project/staticfiles

CORS_ALLOWED_ORIGINS="https://yourdomain.com https://www.yourdomain.com http://frontendapp.example.com"

https://yourdomain.com: основной домен сервера приложения.
https://www.yourdomain.com: дополнительный вариант адреса с префиксом www.
http://frontendapp.example.com: адрес фронтенд-приложения, которое взаимодействует с вашим бэкендом.

SRF_TRUSTED_ORIGINS="https://yourdomain.com https://www.yourdomain.com http://frontendapp.example.com"

ADMIN_LOGIN = admin
ADMIN_EMAIL = свой Майл
ADMIN_PASSWORD = Пароль
ACCESS_TOKEN_COOKIE_SECURE = True


### Запуск локально

# Установка зависимостей
pip install -r requirements.txt
# Cоздание .env (шаблон смотри выше)

# Создание миграций
python manage.py migrate


# Запуск сервера
python manage.py runserver

## Запуск на Reg.ru

# 1. Войти в свой ЛК на Reg.ru

# 2. Настроить SSH ключ
    Запустите терминал на своем ПК (на windows это git-bash)
    Введите команду ssh-keygen( перед созданием команда спросит изменить ли название ключа(можно не менять) и пароль на ключ)
    После создания ключа вводим команду cat ~/.ssh/название вашего ключа.pub
    Копируем ключ

    На reg.ru заходим Виртуальные серверы нажимаем Создать первый сервер
    выбираем операционную систему, тариф, регион размещения, настройки сети, резервное копирование(если нужно). 
    Далее идут Настройки сервера нажимаем новый SSH-Ключ  и вставляем сюда свой скопированный ключ( название ключа выбирайте сами)(название сервера менять можно, если нужно)
    Нажимаем заказать сервер( Ждем пока создается)
    Когда сервер создастся придет на емайл указаный при регистрации на платформе логин и пароль для подключения к серверу
    Далее переходим в терминал
    Вводим      ssh логин@айпи адрес сервера
    Подтверждаем что это известный нам адрес и вводим пароль
    Создаем нового пользователя чтобы не работать под  root пользователем
    adduser имя_пользователя c маленькой буквы
    Далее вводим команду   usermod имя_пользователя -aG sudo добавляя пользователя в группу суперпользователей далее команда logout
    Переключаемся к серверу на созданного пользователя
    После входа обновляем все индексы пакетов командой
    sudo apt update
    Затем можно обновить ПО до последних версий командой
    sudo apt upgrade
    Далее устанавливаем все необходимое ПО командой
    sudo apt install python3-venv pip curl postgresql nginx
    Запускаем nginx командой
    sudo systemctl start nginx
    Сразу проверяем статус работы nginx командой
    sudo systemctl status nginx
    Создаем папку для проекта командой
    mkdir название папки
    Заходим в папку
    cd название папки
    Далее копируем ссылку на репозоторий 
    git clone https://github.com/newr-hide/frontend_cloude_storage.git
    далее
    git clone https://github.com/newr-hide/backend_cloude_storage.git

    Создаем базу данных
    Переключаемся на пользователя postgres командой
    sudo su postgres
    Далее psql
    и задаем постгресюзеру пароль
    ALTER USER postgres WITH PASSWORD 'ваш пароль';
    и создаем базу данных
    CREATE DATABASE название БД;
    выходим из psql командой exit
    выходим из под postgresUser командой exit

    Заходим в папку backend_cloude_storage 
    Создаем файл .env командой
    nano .env и он открывается для редактирования заполняем его по примеру .env.example

    Далее создаем виртуальное окружение для проекта 
    python3 -m venv название окружения
    активируем окружение
    source название окружения/bin/activate
    устанавливаем зависимости
    pip install -r requirements.txt
    Создаем папку static командой
    mkdir backend_cloude_storage/static

    проводим миграции командой
    python manage.py migrate


    Далее установите ПО для сертификата(в данном случае сертификат будет самописный)
    sudo apt install openssl
    создаем директорию для сертификата если ее нет
    sudo mkdir /etc/ssl/private
    генерируем сертификат командой
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout /etc/ssl/private/django.key \
-out /etc/ssl/private/django.crt
При выполнении команды вам нужно будет ввести:
Country Name (2 буквы, например RU)
State or Province Name (например, Moscow)
Locality Name (город)
Organization Name (название организации/проекта)
Common Name (можно указать IP-адрес сервера)
Email Address

Далее ставим права на сертификат
sudo chmod 600 /etc/ssl/private/django.key
sudo chmod 600 /etc/ssl/private/django.crt
Затем создаем
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
и задаем права
sudo chmod 600 /etc/ssl/certs/dhparam.pem
sudo chown root:root /etc/ssl/certs/dhparam.pem
далее проверьте все файлы
sudo ls -la /etc/ssl/private/django.crt
sudo ls -la /etc/ssl/private/django.key
sudo ls -la /etc/ssl/certs/dhparam.pem

Настраиваем nginx откройте конфигурационный файл командой
sudo nano /etc/nginx/sites-available/название
копируйте туда содержимое из файла nginx.conf.example заменяя на свой айпи адрес

создайте новую ссылку командой
sudo ln -s /etc/nginx/sites-available/название /etc/nginx/sites-enabled/
сохраните изменения и проверьте синтаксис на наличие ошибок 
sudo nginx -t
вводим команду
sudo ufw allow 'Nginx Full'

Настраиваем Gunicorn
создаем файл с настройками командой
sudo nano /etc/systemd/system/gunicorn.service
вписываем туда все что есть в файле gunicorn.example
проверяем статус командой
 sudo systemctl status gunicorn













    









### API документация
## Аутентификация
Получение токена: /api/token/

Обновление токена: /api/token/refresh/

Выход: /api/auth/logout/

## Основные эндпоинты
# Пользователи:

Регистрация: POST /api/users/

# Получение информации: GET /api/users/{id}/

# Файлы:

Загрузка: POST /api/files/

# Получение списка: GET /api/files/

# Скачивание: GET /api/download/{pk}/

# Удаление: DELETE /api/files/{pk}/delete/

## Публичный доступ:

# Скачивание по ссылке: GET /api/download-public/{token}/