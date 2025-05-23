import telebot
import os
import logging
import numpy as np
from PIL import Image
from telebot import types, apihelper
import sqlite3
import bcrypt
import time
from flask import Flask, request
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
        cursor.execute("SELECT registered FROM users WHERE id=?", (chat_id,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0]
    except sqlite3.Error as e:
        logger.error(f"Database error in is_registered: {e}")
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


def set_main_menu(chat_id):
    """Установка главного меню"""
    menu = {
        'keyboard': [
            [{"text": "📸 Классифицировать изображение"}],
            [{"text": "📊 Моя статистика"}, {"text": "🆘 Помощь"}]
        ],
        'resize_keyboard': True
    }
    if is_admin(chat_id):
        menu['keyboard'].append([{"text": "👑 Админ-панель"}])
    send_message(chat_id, "🏠 Главное меню\nВыберите действие:", menu)

# Состояния пользователей
class UserState:
    AWAIT_PASSWORD_REGISTER = 1
    AWAIT_PASSWORD_LOGIN = 2
    AWAIT_ADMIN_ACTION = 3
    AWAIT_USER_ID_DELETE = 4
    AWAIT_USER_ID_PROMOTE = 5
    AWAIT_USER_ID_RESET = 6


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
            handle_message(data['message'])
            
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        logger.error(f"Ошибка обработки вебхука: {str(e)}")
        return jsonify({'status': 'error'}), 500

# ... предыдущий код остаётся без изменений ...

def handle_command(chat_id, command, message):
    if command == '/start':
        handle_start(chat_id)
    elif command == '/register':
        start_registration(chat_id)
    elif command == '/login':
        start_login(chat_id)
    elif command == '/logout':
        handle_logout(chat_id)
    elif command == '/admin':
        handle_admin(chat_id)
    elif command == '📸 классифицировать изображение':
        handle_predict_image(chat_id)
    elif command == '📊 моя статистика':
        handle_stats(chat_id)
    elif command == '🆘 помощь':
        handle_help(chat_id)
    else:
        send_message(chat_id, "❌ Неизвестная команда")

def handle_start(chat_id):
    if is_registered(chat_id):
        show_main_menu(chat_id)
    else:
        send_message(chat_id, 
            "👋 Для использования бота необходимо зарегистрироваться.\n"
            "Используйте /register для создания аккаунта")

def start_login(chat_id):
    if is_registered(chat_id):
        user_states[chat_id] = UserState.AWAIT_PASSWORD_LOGIN
        send_message(chat_id, "🔑 Введите ваш пароль:")
    else:
        send_message(chat_id, "❌ Вы не зарегистрированы! Используйте /register")

def process_login(chat_id, password):
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE id=?", (chat_id,))
        result = cursor.fetchone()
        
    if result and check_password(result[0], password):
        send_message(chat_id, "🔓 Вход выполнен!")
        show_main_menu(chat_id)
    else:
        send_message(chat_id, "❌ Неверный пароль!")
    del user_states[chat_id]

def handle_logout(chat_id):
    if chat_id in user_states:
        del user_states[chat_id]
    send_message(chat_id, "🚪 Вы вышли из системы", create_keyboard([]))

def handle_admin(chat_id):
    if not is_admin(chat_id):
        send_message(chat_id, "⛔ Доступ запрещен!")
        return
    
    admin_menu = create_keyboard([
        [{"text": "📋 Список пользователей"}, {"text": "❌ Удалить пользователя"}],
        [{"text": "👑 Добавить администратора"}, {"text": "🔄 Сбросить пароль"}],
        [{"text": "🔙 В главное меню"}]
    ])
    user_states[chat_id] = UserState.AWAIT_ADMIN_ACTION
    send_message(chat_id, "⚙️ Админ-панель:", admin_menu)

def handle_admin_action(chat_id, text):
    if text == "📋 список пользователей":
        show_users_list(chat_id)
    elif text == "❌ удалить пользователя":
        user_states[chat_id] = UserState.AWAIT_USER_ID_DELETE
        send_message(chat_id, "Введите ID пользователя для удаления:")
    elif text == "👑 добавить администратора":
        user_states[chat_id] = UserState.AWAIT_USER_ID_PROMOTE
        send_message(chat_id, "Введите ID пользователя для повышения:")
    elif text == "🔄 сбросить пароль":
        user_states[chat_id] = UserState.AWAIT_USER_ID_RESET
        send_message(chat_id, "Введите ID пользователя для сброса пароля:")
    elif text == "🔙 в главное меню":
        del user_states[chat_id]
        show_main_menu(chat_id)

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
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT prediction_count FROM users WHERE id=?", (chat_id,))
        count = cursor.fetchone()[0]
    send_message(chat_id, f"📊 Вы выполнили {count} классификаций")

def handle_help(chat_id):
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
        with create_connection() as conn:
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        send_message(chat_id, f"✅ Пользователь {user_id} удален!")
    except Exception as e:
        logger.error(f"Ошибка удаления: {str(e)}")
        send_message(chat_id, "❌ Ошибка удаления")
    finally:
        del user_states[chat_id]

def process_user_promote(chat_id, user_id):
    try:
        with create_connection() as conn:
            conn.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
        send_message(chat_id, f"✅ Пользователь {user_id} стал администратором!")
    except Exception as e:
        logger.error(f"Ошибка назначения админа: {str(e)}")
        send_message(chat_id, "❌ Ошибка обновления")
    finally:
        del user_states[chat_id]

def process_password_reset(chat_id, user_id):
    try:
        temp_pass = "temp123"
        with create_connection() as conn:
            conn.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (hash_password(temp_pass), user_id)
            )
        send_message(chat_id, f"✅ Пароль для {user_id} сброшен. Временный пароль: {temp_pass}")
    except Exception as e:
        logger.error(f"Ошибка сброса пароля: {str(e)}")
        send_message(chat_id, "❌ Ошибка сброса пароля")
    finally:
        del user_states[chat_id]

# Обновлённая функция handle_message
def handle_message(message):
    chat_id = message['chat']['id']
    text = message.get('text', '').lower()
    
    if text.startswith('/'):
        handle_command(chat_id, text, message)
    elif chat_id in user_states:
        handle_user_state(chat_id, text)
    else:
        send_message(chat_id, f"Вы написали: {text}")

def handle_user_state(chat_id, text):
    state = user_states.get(chat_id)
    
    if state == UserState.AWAIT_PASSWORD_REGISTER:
        process_password(chat_id, text, message.get('from', {}).get('username'))
    elif state == UserState.AWAIT_PASSWORD_LOGIN:
        process_login(chat_id, text)
    elif state == UserState.AWAIT_ADMIN_ACTION:
        handle_admin_action(chat_id, text)
    elif state == UserState.AWAIT_USER_ID_DELETE:
        process_user_delete(chat_id, int(text))
    elif state == UserState.AWAIT_USER_ID_PROMOTE:
        process_user_promote(chat_id, int(text))
    elif state == UserState.AWAIT_USER_ID_RESET:
        process_password_reset(chat_id, int(text))

# Обработчик изображений
def handle_photo(message):
    chat_id = message['chat']['id']
    timestamp = int(time.time())
    temp_input = os.path.join(TEMP_DIR, f'input_{chat_id}_{timestamp}.jpg')
    temp_output = os.path.join(TEMP_DIR, f'output_{chat_id}_{timestamp}.jpg')

    try:
        os.makedirs(TEMP_DIR, exist_ok=True)
        
        # Загрузка и сохранение изображения
        file_info = bot.get_file(message.photo[-1].file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        with open(temp_input, 'wb') as f:
            f.write(downloaded_file)

        # Обработка изображения
        img = Image.open(temp_input).convert('RGB')
        inverted = Image.eval(img, lambda x: 255 - x)
        inverted.save(temp_output, "JPEG")

        # Анализ и классификация
        gray = inverted.convert('L')
        gray_array = np.array(gray)
        std = gray_array.std()
        result = "дельфин" if std < THRESHOLD else "человек"

        # Отправка результата
        with open(temp_output, 'rb') as photo:
            bot.send_photo(
                chat_id,
                photo,
                caption=f"🔍 Результат: {result}\n"
                        f"📊 Стандартное отклонение: {std:.1f}"
            )

        # Обновление статистики
        with create_connection() as conn:
            conn.execute("UPDATE users SET prediction_count = prediction_count + 1 WHERE id=?", (chat_id,))

    except Exception as e:
        logger.error(f"Ошибка обработки изображения: {str(e)}", exc_info=True)
        bot.reply_to(message, "❌ Ошибка обработки изображения")

    finally:
        # Очистка временных файлов
        for file_path in [temp_input, temp_output]:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
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
