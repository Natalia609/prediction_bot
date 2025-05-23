import telebot
import os
import logging
import numpy as np
from PIL import Image
from telebot import types
import sqlite3
import bcrypt
import time
from flask import Flask, request

# Настройка Flask-приложения
app = Flask(__name__)
# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Инициализация бота
bot = telebot.TeleBot("7478069267:AAGiHm9F4LeuV_UYSnXY7ht0lrZx0LPXwHA")

# Конфигурация для Render
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_DIR = os.path.join(BASE_DIR, 'temp')
DATABASE_PATH = os.path.join(BASE_DIR, 'users.db')
WEBHOOK_URL = 'https://prediction-bot-1-0753.onrender.com/webhook'  # Будет установлен в настройках Render
PORT = int(os.environ.get('PORT', 10000))  # Render использует порт 10000 по умолчанию

# Параметры алгоритма
THRESHOLD = 45  # Пороговое значение стандартного отклонения
IMAGE_SIZE = (200, 200)  # Размер для ресайза изображений


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


def get_main_menu_keyboard(chat_id):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.row("📸 Классифицировать изображение")
    markup.row("📊 Моя статистика", "🆘 Помощь")
    if is_admin(chat_id):
        markup.row("👑 Админ-панель")
    return markup


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
    
@bot.middleware_handler(update_types=['message'])
def log_messages(bot_instance, message):
    logger.info(f"Received message: {message.text} | Chat ID: {message.chat.id} | User: {message.from_user.username}")

# Обработчики команд
@bot.message_handler(commands=['start'])
def send_welcome(message):
    chat_id = message.chat.id
    if is_registered(chat_id):
        show_main_menu(chat_id)
    else:
        bot.send_message(chat_id,
                         "👋 Добро пожаловать! Для использования бота необходимо зарегистрироваться.\n"
                         "Используйте команду /register для создания аккаунта")


def show_main_menu(chat_id):
    text = "🏠 Главное меню\nВыберите действие:"
    bot.send_message(chat_id, text, reply_markup=get_main_menu_keyboard(chat_id))


@bot.message_handler(commands=['register'])
def register_user(message):
    chat_id = message.chat.id
    if is_registered(chat_id):
        bot.send_message(chat_id, "❌ Вы уже зарегистрированы!")
        return

    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE id=?", (chat_id,))

    if cursor.fetchone():
        bot.send_message(chat_id, "❌ Вы уже зарегистрированы!")
    else:
        user_states[chat_id] = UserState.AWAIT_PASSWORD_REGISTER
        bot.send_message(chat_id,
                         "🔐 Придумайте и введите пароль для регистрации (минимум 8 символов, включая буквы и цифры):")
    conn.close()


@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == UserState.AWAIT_PASSWORD_REGISTER)
def process_password(message):
    chat_id = message.chat.id
    password = message.text

    if not is_password_strong(password):
        bot.send_message(chat_id, "❌ Пароль слишком простой! Используйте не менее 8 символов, включая буквы и цифры.")
        return

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE is_admin=1 LIMIT 1")
    is_admin_flag = 0 if cursor.fetchone() else 1

    cursor.execute('''
        INSERT INTO users 
        (id, username, password_hash, is_admin, registered)
        VALUES (?, ?, ?, ?, 1)
    ''', (chat_id, message.from_user.username, hash_password(password), is_admin_flag))

    conn.commit()
    conn.close()
    del user_states[chat_id]

    # Выводим полное меню после регистрации
    text = "🎉 Регистрация успешна!"
    if is_admin(chat_id):
        text += "\n⚡ Вы стали администратором, так как зарегистрировались первым!"

    bot.send_message(chat_id, text)
    show_main_menu(chat_id)

@bot.message_handler(content_types=['text'])
def text_handler(message):
    try:
        response = f"Вы написали: {message.text}"
        logger.info(f"Preparing response: {response}")
        bot.send_message(message.chat.id, response)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        
@bot.message_handler(commands=['login'])
def login_user(message):
    chat_id = message.chat.id
    user_states[chat_id] = UserState.AWAIT_PASSWORD_LOGIN
    bot.send_message(chat_id, "🔑 Введите ваш пароль:")


@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == UserState.AWAIT_PASSWORD_LOGIN)
def process_login(message):
    chat_id = message.chat.id
    password = message.text
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE id=?", (chat_id,))
    result = cursor.fetchone()

    if result and check_password(result[0], password):
        bot.send_message(chat_id, "🔓 Вход выполнен!")
        show_main_menu(chat_id)
    else:
        bot.send_message(chat_id, "❌ Неверный пароль!")
    conn.close()
    del user_states[chat_id]


@bot.message_handler(commands=['logout'])
@check_registration
def logout_user(message):
    chat_id = message.chat.id
    if chat_id in user_states:
        del user_states[chat_id]
    bot.send_message(chat_id, "🚪 Вы вышли из системы", reply_markup=types.ReplyKeyboardRemove())


@bot.message_handler(commands=['admin'])
@check_registration
def admin_panel(message):
    chat_id = message.chat.id
    if not is_admin(chat_id):
        bot.send_message(chat_id, "⛔ Доступ запрещен!")
        return

    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.row("📋 Список пользователей", "❌ Удалить пользователя")
    markup.row("👑 Добавить администратора", "🔄 Сбросить пароль")
    markup.row("🔙 В главное меню")
    user_states[chat_id] = UserState.AWAIT_ADMIN_ACTION
    bot.send_message(chat_id, "⚙️ Админ-панель:", reply_markup=markup)


@bot.message_handler(func=lambda message: message.text == "📸 Классифицировать изображение")
@check_registration
def predict_image_handler(message):
    bot.send_message(message.chat.id, "📸 Отправьте изображение для классификации")


@bot.message_handler(func=lambda message: message.text == "📊 Моя статистика")
@check_registration
def show_stats_handler(message):
    chat_id = message.chat.id
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT prediction_count FROM users WHERE id=?", (chat_id,))
    count = cursor.fetchone()[0]
    conn.close()
    bot.send_message(chat_id, f"📊 Вы выполнили {count} классификаций")


@bot.message_handler(func=lambda message: message.text == "🆘 Помощь")
@check_registration
def show_help(message):
    chat_id = message.chat.id
    text = (
        "🆘 Список доступных команд:\n\n"
        "/start - Главное меню\n"
        "/login - Войти в аккаунт\n"
        "/logout - Выйти из аккаунта\n"
        "📸 Классифицировать изображение - определить, человек или дельфин на фото\n"
        "📊 Моя статистика - показать количество выполненных классификаций\n"
    )
    if is_admin(chat_id):
        text += "/admin - Админ-панель\n"
    bot.send_message(chat_id, text)


# Обработчик админ-действий
@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == UserState.AWAIT_ADMIN_ACTION)
def handle_admin_actions(message):
    chat_id = message.chat.id

    if message.text == "📋 Список пользователей":
        conn = create_connection()
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
        conn.close()
        bot.send_message(chat_id, response)

    elif message.text == "❌ Удалить пользователя":
        user_states[chat_id] = UserState.AWAIT_USER_ID_DELETE
        bot.send_message(chat_id, "Введите ID пользователя для удаления:")

    elif message.text == "👑 Добавить администратора":
        user_states[chat_id] = UserState.AWAIT_USER_ID_PROMOTE
        bot.send_message(chat_id, "Введите ID пользователя для повышения:")

    elif message.text == "🔄 Сбросить пароль":
        user_states[chat_id] = UserState.AWAIT_USER_ID_RESET
        bot.send_message(chat_id, "Введите ID пользователя для сброса пароля:")

    elif message.text == "🔙 В главное меню":
        del user_states[chat_id]
        show_main_menu(chat_id)


@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == UserState.AWAIT_USER_ID_DELETE)
def process_user_delete(message):
    chat_id = message.chat.id
    try:
        user_id = int(message.text)
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        bot.send_message(chat_id, f"✅ Пользователь {user_id} удален!")
    except Exception as e:
        logger.error(f"Ошибка удаления: {e}")
        bot.send_message(chat_id, "❌ Ошибка удаления")
    finally:
        del user_states[chat_id]


@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == UserState.AWAIT_USER_ID_PROMOTE)
def process_user_promote(message):
    chat_id = message.chat.id
    try:
        user_id = int(message.text)
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        bot.send_message(chat_id, f"✅ Пользователь {user_id} стал администратором!")
    except Exception as e:
        logger.error(f"Ошибка назначения админа: {e}")
        bot.send_message(chat_id, "❌ Ошибка обновления")
    finally:
        del user_states[chat_id]


@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == UserState.AWAIT_USER_ID_RESET)
def process_password_reset(message):
    chat_id = message.chat.id
    try:
        user_id = int(message.text)
        temp_pass = "temp123"
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (hash_password(temp_pass), user_id))
        conn.commit()
        conn.close()
        bot.send_message(chat_id, f"✅ Пароль для {user_id} сброшен. Временный пароль: {temp_pass}")
    except Exception as e:
        logger.error(f"Ошибка сброса пароля: {e}")
        bot.send_message(chat_id, "❌ Ошибка сброса пароля")
    finally:
        del user_states[chat_id]


# Обработчик изображений
@bot.message_handler(content_types=['photo'])
@check_registration
def handle_photo(message):
    chat_id = message.chat.id
    timestamp = int(time.time())
    temp_input = os.path.join(TEMP_DIR, f'input_{chat_id}_{timestamp}.jpg')
    temp_output = os.path.join(TEMP_DIR, f'output_{chat_id}_{timestamp}.jpg')

    try:
        # Создаем папку temp если не существует
        os.makedirs(TEMP_DIR, exist_ok=True)
        # Загрузка изображения
        file_info = bot.get_file(message.photo[-1].file_id)
        downloaded_file = bot.download_file(file_info.file_path)

        # Сохранение оригинального изображения
        with open(temp_input, 'wb') as f:
            f.write(downloaded_file)

        # Обработка изображения
        img = Image.open(temp_input)
        img = img.convert('RGB')

        # Инвертирование цветов
        inverted = Image.eval(img, lambda x: 255 - x)

        # Сохранение инвертированного изображения
        inverted.save(temp_output, "JPEG")

        # Анализ для классификации
        gray = inverted.convert('L')
        gray_array = np.array(gray)
        std = gray_array.std()
        result = "дельфин" if std < THRESHOLD else "человек"

        # Отправка результата и изображения
        with open(temp_output, 'rb') as photo:
            bot.send_photo(
                chat_id,
                photo
            )

        # Обновление статистики
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET prediction_count = prediction_count + 1 WHERE id=?", (chat_id,))
        conn.commit()
        conn.close()


    except Exception as e:
        logger.error(f"Ошибка обработки изображения: {e}")
        bot.reply_to(message, "❌ Ошибка обработки изображения")


    finally:
        # Удаление временных файлов
        for file_path in [temp_input, temp_output]:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.error(f"Ошибка удаления файла {file_path}: {e}")
 # Веб-хук обработчик

    @app.route('/webhook', methods=['POST'])
    def webhook():
        logger.info("Incoming webhook request")  # Добавьте логирование
        if request.headers.get('content-type') == 'application/json':
            json_data = request.get_data().decode('utf-8')
            update = telebot.types.Update.de_json(json_data)
            bot.process_new_updates([update])
            return 'OK', 200
        logger.error("Invalid request content-type")
        return 'Invalid request', 403

    @app.route('/')
    def home():

        return "Telegram Bot is Running!"


if __name__ == '__main__':
    os.makedirs(TEMP_DIR, exist_ok=True)
    init_db()
    
    # Настройка вебхука
    bot.remove_webhook()
    time.sleep(1)
    bot.set_webhook("https://prediction-bot-1-0753.onrender.com/webhook")  # Добавьте кавычки
    
    # Запуск приложения
    app.run(host='0.0.0.0', port=PORT)
