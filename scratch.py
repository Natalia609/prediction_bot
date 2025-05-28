import telebot
import os
import logging
import numpy as np
from PIL import Image
from telebot import types, apihelper
import sqlite3
from telegram import ReplyKeyboardMarkup
import bcrypt
import json
import time
from flask import Flask, request, jsonify
import requests  # Добавить эту строку в секцию импортов

TOKEN = '7478069267:AAGiHm9F4LeuV_UYSnXY7ht0lrZx0LPXwHA'
# Настройка Flask-приложения
app = Flask(__name__)
# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


apihelper.ENABLE_MIDDLEWARE = True
# Инициализация бота

# Конфигурация для Render
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_DIR = os.path.join(BASE_DIR, 'temp')
DATABASE_PATH = os.path.join(BASE_DIR, 'users.db')
WEBHOOK_URL = 'https://prediction-bot-1-0753.onrender.com/webhook'  # Будет установлен в настройках Render
PORT = int(os.environ.get('PORT', 10000))  # Render использует порт 10000 по умолчанию

# Параметры алгоритма
THRESHOLD = 45  # Пороговое значение стандартного отклонения
IMAGE_SIZE = (200, 200)  # Размер для ресайза изображений

def check_telegram_connection():
    try:
        response = requests.get(
            f"https://api.telegram.org/bot7478069267:AAGiHm9F4LeuV_UYSnXY7ht0lrZx0LPXwHA/getMe",
            timeout=5
        )
        logger.info(f"Статус подключения: {response.status_code}")
        logger.debug(f"Ответ Telegram API: {response.text}")
    except Exception as e:
        logger.error(f"Ошибка подключения: {str(e)}")

# Вызовите при старте
check_telegram_connection()
# Инициализация базы данных
def create_connection():
    return sqlite3.connect('users.db', check_same_thread=False)


def init_db():
    db_path = 'users.db'
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT registered FROM users LIMIT 1")
            conn.close()
        except sqlite3.OperationalError:
            os.remove(db_path)
            logger.info("Удалена старая база данных из-за ошибки структуры")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password_hash TEXT,
            is_admin BOOLEAN DEFAULT 0,
            prediction_count INTEGER DEFAULT 0,
            registered BOOLEAN DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()


init_db()


# Вспомогательные функции
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')


def check_password(hashed, password):
    return bcrypt.checkpw(password.encode(), hashed.encode('utf-8'))


def is_password_strong(password):
    return len(password) >= 8 and any(c.isdigit() for c in password) and any(c.isalpha() for c in password)


def is_registered(chat_id):
    try:
        conn = create_connection()
        cursor = conn.cursor()
        # Добавляем проверку registered=1
        cursor.execute("SELECT id FROM users WHERE id=? AND registered=1", (chat_id,))
        result = cursor.fetchone() is not None
        conn.close()
        logger.debug(f"Проверка регистрации {chat_id}: {result}")
        return result
    except sqlite3.Error as e:
        logger.error(f"Ошибка БД в is_registered: {e}")
        return False
        
def is_admin(chat_id):
    try:
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE id=?", (chat_id,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0]
    except sqlite3.Error as e:
        logger.error(f"Database error in is_admin: {e}")
        return False
def send_message(chat_id, text, reply_markup=None):
    """Отправка сообщения через Telegram API"""
    url = f'https://api.telegram.org/bot{TOKEN}/sendMessage'
    payload = {
        'chat_id': chat_id,
        'text': text,
        'parse_mode': 'HTML'
    }
    
    if reply_markup:
        payload['reply_markup'] = json.dumps(reply_markup)
        
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        logger.info(f"Сообщение отправлено в {chat_id}")
        return True
    except Exception as e:
        logger.error(f"Ошибка отправки: {str(e)}")
        return False
        
def create_keyboard(buttons, resize=True, one_time=False):
    """Создает клавиатуру в формате Telegram API"""
    return {
        "keyboard": buttons,
        "resize_keyboard": resize,
        "one_time_keyboard": one_time
    }


def set_main_menu(chat_id):
    """Обновление главного меню"""
    if not check_auth(chat_id):
        return
    buttons = [
        [{"text": "📸 Классифицировать изображение"}],
        [{"text": "📊 Моя статистика"}, {"text": "🆘 Помощь"}]
    ]
    
    if is_admin(chat_id):
        buttons.append([{"text": "👑 Админ-панель"}])
    
    keyboard = create_keyboard(buttons)
    send_message(chat_id, "🏠 Главное меню\nВыберите действие:", reply_markup=keyboard)
    
logged_users = set()  # Множество для отслеживания авторизованных пользователей
# Состояния пользователей
class UserState:
    AWAIT_PASSWORD_REGISTER = 1
    AWAIT_PASSWORD_LOGIN = 2
    AWAIT_ADMIN_ACTION = 3
    AWAIT_USER_ID_DELETE = 4
    AWAIT_USER_ID_PROMOTE = 5
    AWAIT_USER_ID_RESET = 6
    LOGGED_IN = 7
    LOGGED_OUT = 8  # Новое состояние


user_states = {}


# Декоратор для проверки регистрации
def check_registration(func):
    def wrapper(message):
        if not is_registered(message.chat.id):
            bot.send_message(message.chat.id, "⚠️ Пожалуйста, сначала зарегистрируйтесь с помощью /register")
            return
        return func(message)

    return wrapper

@app.route('/webhook', methods=['POST'])
def webhook_handler():
    try:
        data = request.get_json()
        logger.debug(f"Получено обновление: {data}")
        
        if 'message' in data:
            message = data['message']
            
            # Обработка фото
            if 'photo' in message:
                handle_photo(message)
                return jsonify({'status': 'ok'}), 200
            
            # Обработка текста
            chat = message.get('chat', {})
            chat_id = chat.get('id')
            text = message.get('text', '').strip()
            username = message.get('from', {}).get('username')

            if chat_id:
                if user_states.get(chat_id):
                    handle_user_state(chat_id, text, message)
                else:
                    handle_command(chat_id, text, message)
            
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        logger.error(f"Ошибка обработки вебхука: {str(e)}", exc_info=True)
        return jsonify({'status': 'error'}), 500

# ... предыдущий код остаётся без изменений ...
def start_registration(chat_id):
    try:
        if chat_id in user_states:
            send_message(chat_id, "⚠️ Завершите текущий процесс регистрации!")
            return
            
        if is_registered(chat_id):
            send_message(chat_id, "❌ Вы уже зарегистрированы!")
            return
        
        user_states[chat_id] = UserState.AWAIT_PASSWORD_REGISTER
        send_message(chat_id, "🔐 Придумайте пароль (минимум 8 символов, буквы и цифры):")
        
    except Exception as e:
        logger.error(f"Ошибка старта регистрации: {str(e)}")
        send_message(chat_id, "❌ Ошибка инициализации регистрации")

def process_password(chat_id, password, username):
    try:
        # Проверка сложности пароля
        if not is_password_strong(password):
            send_message(chat_id, "❌ Пароль должен содержать минимум 8 символов, буквы и цифры!")
            return

        with create_connection() as conn:
            cursor = conn.cursor()
            
            try:
                # Начало транзакции
                conn.execute("BEGIN IMMEDIATE")
                
                # Проверка существующей регистрации с блокировкой
                cursor.execute("SELECT id FROM users WHERE id=? LIMIT 1", (chat_id,))
                if cursor.fetchone():
                    logger.warning(f"Попытка повторной регистрации: {chat_id}")
                    send_message(chat_id, "❌ Вы уже зарегистрированы!")
                    conn.rollback()
                    return

                # Определение роли администратора
                cursor.execute("SELECT id FROM users WHERE is_admin=1 LIMIT 1")
                is_admin_flag = 0 if cursor.fetchone() else 1

                # Вставка данных с обработкой конфликтов
                cursor.execute('''
                    INSERT OR IGNORE INTO users 
                        (id, username, password_hash, is_admin, registered)
                    VALUES (?, ?, ?, ?, 1)
                ''', (chat_id, username, hash_password(password), is_admin_flag))
                
                if cursor.rowcount == 0:
                    raise sqlite3.IntegrityError("Duplicate user ID")
                
                conn.commit()
                logger.info(f"Успешная регистрация: {chat_id}")

            except sqlite3.IntegrityError as e:
                logger.error(f"Конфликт данных: {str(e)}")
                send_message(chat_id, "❌ Аккаунт уже существует!")
                conn.rollback()
                return
                
            except Exception as e:
                logger.error(f"Ошибка БД: {str(e)}")
                conn.rollback()
                raise

        # Обновление интерфейса
        if chat_id in user_states:
            del user_states[chat_id]
            
        text = "🎉 Регистрация успешна!" + ("\n⚡ Вы стали администратором!" if is_admin_flag else "")
        send_message(chat_id, text)
        set_main_menu(chat_id)

    except Exception as e:
        logger.error(f"Критическая ошибка: {str(e)}\n{traceback.format_exc()}")
        send_message(chat_id, "❌ Внутренняя ошибка сервера. Попробуйте позже.")
    
def handle_command(chat_id, command, message):
    # Блокировка всех команд кроме регистрации/входа
    if command.lower() in ['/start', '/register', '/login']:
        if command == '/start':
            handle_start(chat_id)
        elif command == '/register':
            start_registration(chat_id)
        elif command == '/login':
            start_login(chat_id)
        return
    
    # Для остальных команд проверяем авторизацию
    if not is_logged_in(chat_id):
        send_message(chat_id, "🔒 Требуется авторизация! Используйте /login")
        return
            
    if command == '/start':
        handle_start(chat_id)
    elif command == '/register':
        start_registration(chat_id)
    elif command == '/login':
        start_login(chat_id)
    elif command == '/logout':
        handle_logout(chat_id)
    elif command == "👑 Админ-панель":
        handle_admin(chat_id)
    elif command == '📸 Классифицировать изображение':
        handle_predict_image(chat_id)
    elif command == '📊 Моя статистика':
        handle_stats(chat_id)
    elif command == '🆘 Помощь':
        handle_help(chat_id)    
    else:
        send_message(chat_id, "❌ Неизвестная команда")
        
def handle_start(chat_id):
    if is_registered(chat_id):
        if is_logged_in(chat_id):
            set_main_menu(chat_id)
        else:
            # Добавляем клавиатуру для входа
            keyboard = create_keyboard([["/login"]])
            send_message(chat_id, "🔒 Требуется вход. Используйте /login", reply_markup=keyboard)
    else:
        # Клавиатура для регистрации
        keyboard = create_keyboard([["/register"]])
        send_message(
            chat_id, 
            "👋 Для использования бота необходимо зарегистрироваться.\nИспользуйте /register", 
            reply_markup=keyboard
        )
        
def start_login(chat_id):
    if chat_id in user_states:
        send_message(chat_id, "⚠️ Завершите текущую операцию!")
        return
        
    if is_registered(chat_id):
        user_states[chat_id] = UserState.AWAIT_PASSWORD_LOGIN
        send_message(chat_id, "🔑 Введите ваш пароль:")
    else:
        send_message(chat_id, "❌ Вы не зарегистрированы! Используйте /register")


def process_login(chat_id, password):
    try:
        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE id=?", (chat_id,))
            result = cursor.fetchone()
        
        if result and check_password(result[0], password):
            logged_users.add(chat_id)
            
            # Принудительное обновление интерфейса
            set_main_menu(chat_id)
            send_message(chat_id, "🔓 Вход выполнен!")
            set_main_menu(chat_id)
        else:
            send_message(chat_id, "❌ Неверный пароль!")
            
    except Exception as e:
        logger.error(f"Ошибка входа: {str(e)}")
        send_message(chat_id, "❌ Ошибка сервера при входе")
    
    finally:
        if chat_id in user_states:
            del user_states[chat_id]
        
def is_logged_in(chat_id):
    """Проверка статуса авторизации с учетом всех условий"""
    # Основная проверка авторизации и состояния
    
    if chat_id in logged_users:
        return True
    
    # Резервная проверка в БД
    try:
        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT registered FROM users WHERE id=?", (chat_id,))
            result = cursor.fetchone()
            if result and result[0]:
                logged_users.add(chat_id)  # Восстанавливаем статус
                return True
    except Exception as e:
        logger.error(f"Ошибка проверки авторизации: {str(e)}")
    
    return False

def check_auth(chat_id):
    """Проверка авторизации с разрешением регистрации/входа"""
    if not is_registered(chat_id) and user_states.get(chat_id) != UserState.AWAIT_PASSWORD_REGISTER:
        # Разрешаем процесс регистрации
        return True
    return chat_id in logged_users


def handle_logout(chat_id):
    if chat_id in logged_users:
        logged_users.remove(chat_id)
    if chat_id in user_states:
        del user_states[chat_id]
    
    # Создаем клавиатуру с кнопками регистрации и входа
    keyboard = create_keyboard([["/register", "/login"]])
    send_message(
        chat_id, 
        "🚪 Вы вышли из системы. Для продолжения:", 
        reply_markup=keyboard
    )
    
def handle_admin(chat_id):
    # Добавляем проверку авторизации
    if not is_registered(chat_id):
        send_message(chat_id, "❌ Сначала выполните вход!")
        return
        
    if not is_admin(chat_id):
        send_message(chat_id, "⛔ Доступ запрещен!")
        return
    
    # Убедимся, что клавиатура создается правильно
    admin_buttons = [
        [{"text": "📋 Список пользователей"}, {"text": "❌ Удалить пользователя"}],
        [{"text": "👑 Добавить администратора"}, {"text": "🔄 Сбросить пароль"}],
        [{"text": "🔙 В главное меню"}]
    ]
    admin_menu = create_keyboard(admin_buttons)
    
    # Обновляем состояние
    user_states[chat_id] = UserState.AWAIT_ADMIN_ACTION
    send_message(chat_id, "⚙️ Админ-панель:", reply_markup=admin_menu)

def handle_admin_action(chat_id, text):
    if text == "📋 Список пользователей":
        show_users_list(chat_id)
    elif text == "❌ Удалить пользователя":
        user_states[chat_id] = UserState.AWAIT_USER_ID_DELETE
        send_message(chat_id, "Введите ID пользователя для удаления:")
    elif text == "👑 Добавить администратора":
        user_states[chat_id] = UserState.AWAIT_USER_ID_PROMOTE
        send_message(chat_id, "Введите ID пользователя для повышения:")
    elif text == "🔄 Сбросить пароль":
        user_states[chat_id] = UserState.AWAIT_USER_ID_RESET
        send_message(chat_id, "Введите ID пользователя для сброса пароля:")
    elif text == "🔙 В главное меню":
        del user_states[chat_id]
        set_main_menu(chat_id)

def show_users_list(chat_id):
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, is_admin, prediction_count FROM users")
        users = cursor.fetchall()
    
    response = "👥 Список пользователей:\n\n"
    for user in users:
        response += (
            f"🆔 ID: {user[0]}\n"
            f"👤 Имя: {user[1]}\n"
            f"👑 Админ: {'Да' if user[2] else 'Нет'}\n"
            f"📊 Предсказаний: {user[3]}\n\n"
        )
    send_message(chat_id, response)

def handle_predict_image(chat_id):
    if not is_registered(chat_id):
        send_message(chat_id, "❌ Необходима регистрация!")
        return
    send_message(chat_id, "📸 Отправьте изображение для классификации")

def handle_stats(chat_id):
    if not is_registered(chat_id):
        send_message(chat_id, "❌ Необходима регистрация!")
        return
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT prediction_count FROM users WHERE id=?", (chat_id,))
        count = cursor.fetchone()[0]
    send_message(chat_id, f"📊 Вы выполнили {count} классификаций")

def handle_help(chat_id):
    if not is_registered(chat_id):
        send_message(chat_id, "❌ Необходима регистрация!")
        return
    help_text = (
        "🆘 Список команд:\n"
        "/start - Главное меню\n"
        "/register - Регистрация\n"
        "/login - Вход\n"
        "/logout - Выход\n"
        "/admin - Админ-панель (для администраторов)\n"
        "📸 Классифицировать изображение\n"
        "📊 Моя статистика\n"
        "🆘 Помощь"
    )
    send_message(chat_id, help_text)

# Обработка администраторских действий
def process_user_delete(chat_id, user_id):
   try:
        # Проверка существования пользователя
        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE id=?", (user_id,))
            if not cursor.fetchone():
                send_message(chat_id, f"❌ Пользователь с ID {user_id} не найден!")
                return False
                
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()
            
        send_message(chat_id, f"✅ Пользователь {user_id} удален!")
        return True
    except Exception as e:
        logger.error(f"Ошибка удаления: {str(e)}")
        send_message(chat_id, "❌ Ошибка удаления")
        return False

def process_user_promote(chat_id, user_id):
    try:
        # Проверка существования пользователя
        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE id=?", (user_id,))
            if not cursor.fetchone():
                send_message(chat_id, f"❌ Пользователь с ID {user_id} не найден!")
                return False
                
            cursor.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
            conn.commit()
            
        send_message(chat_id, f"✅ Пользователь {user_id} стал администратором!")
        return True
    except Exception as e:
        logger.error(f"Ошибка назначения админа: {str(e)}")
        send_message(chat_id, "❌ Ошибка обновления")
        return False

def process_password_reset(chat_id, user_id):
    try:
        # Проверка существования пользователя
        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE id=?", (user_id,))
            if not cursor.fetchone():
                send_message(chat_id, f"❌ Пользователь с ID {user_id} не найден!")
                return False
                
            temp_pass = "temp123"
            cursor.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (hash_password(temp_pass), user_id)
            )
            conn.commit()
            
        send_message(chat_id, f"✅ Пароль для {user_id} сброшен. Временный пароль: {temp_pass}")
        return True
    except Exception as e:
        logger.error(f"Ошибка сброса пароля: {str(e)}")
        send_message(chat_id, "❌ Ошибка сброса пароля")
        return False

# Обновлённая функция handle_message
def handle_message(message):
    chat_id = message['chat']['id']
    if not check_auth(chat_id) and message.get('text') not in ['/register', '/login']:
        return
    text = message.get('text', '').lower()
    
    if text.startswith('/'):
        handle_command(chat_id, text, message)
    elif chat_id in user_states:
        handle_user_state(chat_id, text)
    else:
        send_message(chat_id, f"Вы написали: {text}")

def handle_user_state(chat_id, text, message):  # Добавляем параметр message
    state = user_states.get(chat_id)
    
    if state == UserState.AWAIT_PASSWORD_REGISTER:
        username = message.get('from', {}).get('username', 'unknown')
        process_password(chat_id, text, username)
        
    elif state == UserState.AWAIT_PASSWORD_LOGIN:
        process_login(chat_id, text)
        
    elif state == UserState.AWAIT_ADMIN_ACTION:
        handle_admin_action(chat_id, text)
        
    # Обработка администраторских действий с проверкой ввода
    elif state == UserState.AWAIT_USER_ID_DELETE:
        try:
            user_id = int(text)
            if process_user_delete(chat_id, user_id):
                del user_states[chat_id]  # Успешно завершено
        except ValueError:
            send_message(chat_id, "❌ Ожидается числовой ID пользователя. Пожалуйста, введите корректный ID:")
            # Остаемся в том же состоянии для повторного ввода
            
    elif state == UserState.AWAIT_USER_ID_PROMOTE:
        try:
            user_id = int(text)
            if process_user_promote(chat_id, user_id):
                del user_states[chat_id]  # Успешно завершено
        except ValueError:
            send_message(chat_id, "❌ Ожидается числовой ID пользователя. Пожалуйста, введите корректный ID:")
            # Остаемся в том же состоянии для повторного ввода
            
    elif state == UserState.AWAIT_USER_ID_RESET:
        try:
            user_id = int(text)
            if process_password_reset(chat_id, user_id):
                del user_states[chat_id]  # Успешно завершено
        except ValueError:
            send_message(chat_id, "❌ Ожидается числовой ID пользователя. Пожалуйста, введите корректный ID:")
# Обработчик изображений
def handle_photo(message_data):
    try:
        # Извлекаем данные из сообщения
        chat_id = message_data['chat']['id']
        if not check_auth(chat_id):
            return
        photos = message_data.get('photo', [])
        
        if not photos:
            send_message(chat_id, "❌ Не удалось получить изображение")
            return

        # Выбираем фото максимального качества
        photo = max(photos, key=lambda x: x['file_size']) if len(photos) > 1 else photos[-1]
        file_id = photo['file_id']

        # Получаем URL файла
        file_info_url = f"https://api.telegram.org/bot{TOKEN}/getFile?file_id={file_id}"
        file_response = requests.get(file_info_url).json()
        
        if not file_response.get('ok'):
            raise Exception("File info request failed")

        file_path = file_response['result']['file_path']
        download_url = f"https://api.telegram.org/file/bot{TOKEN}/{file_path}"

        # Скачиваем изображение
        response = requests.get(download_url)
        if response.status_code != 200:
            raise Exception("Failed to download image")

        # Создаем временные файлы
        timestamp = int(time.time())
        os.makedirs(TEMP_DIR, exist_ok=True)
        input_path = os.path.join(TEMP_DIR, f'input_{chat_id}_{timestamp}.jpg')
        output_path = os.path.join(TEMP_DIR, f'output_{chat_id}_{timestamp}.jpg')

        # Сохраняем и обрабатываем изображение
        with open(input_path, 'wb') as f:
            f.write(response.content)

        # Инвертируем цвета
        with Image.open(input_path) as img:
            rgb_img = img.convert('RGB')
            inverted = Image.eval(rgb_img, lambda x: 255 - x)
            inverted.save(output_path, "JPEG")

        # Отправляем результат
        with open(output_path, 'rb') as photo_file:
            files = {'photo': photo_file}
            caption = "🖼 Обработанное изображение (инвертированные цвета)"
            response = requests.post(
                f"https://api.telegram.org/bot{TOKEN}/sendPhoto",
                data={'chat_id': chat_id, 'caption': caption},
                files=files
            )

        if response.status_code != 200:
            raise Exception("Failed to send photo")

        # Обновляем статистику
        with create_connection() as conn:
            conn.execute("UPDATE users SET prediction_count = prediction_count + 1 WHERE id=?", (chat_id,))
            conn.commit()

    except Exception as e:
        logger.error(f"Ошибка обработки изображения: {str(e)}", exc_info=True)
        send_message(chat_id, "❌ Произошла ошибка при обработке изображения")
    
    finally:
        # Удаляем временные файлы
        for path in [input_path, output_path]:
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except Exception as e:
                logger.error(f"Ошибка удаления файла: {str(e)}")

# Веб-хук обработчик

@app.route('/')
def home():
    return "Telegram Bot is Running!", 200

if __name__ == '__main__':
    # Настройка вебхука
    try:
        response = requests.post(
            f'https://api.telegram.org/bot{TOKEN}/setWebhook',
            json={'url': WEBHOOK_URL}
        )
        logger.info(f"Вебхук установлен: {response.json()}")
    except Exception as e:
        logger.error(f"Ошибка настройки вебхука: {str(e)}")
    
    app.run(host='0.0.0.0', port=10000)
