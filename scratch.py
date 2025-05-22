import telebot
import os
import logging
import numpy as np
import tensorflow as tf
from keras.utils import load_img, img_to_array
from telebot import types
import sqlite3
import bcrypt
from flask import Flask, request, abort
import secrets
import io

SECRET_TOKEN = "Jt9V3Lp"
TELEGRAM_TOKEN="7478069267:AAH3DIWIPLa9NXwN7bwpU5i7VkTychXeFqw"
PORT = int(os.environ.get('PORT', 10000))

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Инициализация бота и Flask
bot = telebot.TeleBot(TELEGRAM_TOKEN)
app = Flask(__name__)

# Конфигурация модели
MODEL_URL = "https://github.com/Natalia609/prediction_bot/releases/download/v1.0.0/people_dolphin_classifier.h5"
MODEL_PATH = "people_dolphin_classifier.h5"


def download_model():
    """Скачивает и кэширует модель"""
    if not os.path.exists(MODEL_PATH):
        logger.info("Downloading model...")
        try:
            response = requests.get(MODEL_URL, stream=True)
            response.raise_for_status()
            with open(MODEL_PATH, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info("Model downloaded successfully!")
        except Exception as e:
            logger.error(f"Model download failed: {e}")
            raise


# Инициализация модели
try:
    download_model()
    model = tf.keras.models.load_model(MODEL_PATH)
    logger.info("Model loaded successfully!")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    model = None
    if os.environ.get('REQUIRE_MODEL', 'True') == 'True':
        exit(1)


# Webhook handling
@app.route('/webhook', methods=['POST'])
def webhook():
    if request.headers.get('X-Telegram-Bot-Api-Secret-Token') != SECRET_TOKEN:
        abort(403)

    if request.content_type == 'application/json':
        json_data = request.get_json()
        update = telebot.types.Update.de_json(json_data)
        bot.process_new_updates([update])
        return '', 200
    abort(400)


def set_telegram_webhook():
    webhook_url = f"{os.environ.get('RENDER_EXTERNAL_URL')}/webhook"

    try:
        response = requests.post(
            f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/setWebhook',
            json={
                'url': webhook_url,
                'secret_token': SECRET_TOKEN,
                'allowed_updates': ['message', 'callback_query'],
                'drop_pending_updates': True
            },
            timeout=10
        )
        response.raise_for_status()
        logger.info(f"Webhook set to: {webhook_url}")
        return True
    except Exception as e:
        logger.error(f"Webhook setup error: {e}")
        return False


# Оптимизированная работа с базой данных
def create_connection():
    return sqlite3.connect(
        os.path.join(os.getcwd(), 'users.db'),
        check_same_thread=False,
        timeout=10
    )


def init_db():
    with create_connection() as conn:
        conn.execute('''
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
    try:
        # Оптимизированная загрузка изображения в память
        file_info = bot.get_file(message.photo[-1].file_id)
        downloaded = bot.download_file(file_info.file_path)

        # Обработка изображения без сохранения на диск
        img = load_img(io.BytesIO(downloaded), target_size=(200, 200))
        x = img_to_array(img)
        x = np.expand_dims(x, axis=0) / 255.0

        # Предсказание
        if model:
            pred = model.predict(x)[0][0]
            result = "дельфин" if pred > 0.5 else "человек"
            confidence = pred if pred > 0.5 else 1 - pred
            response = f"🔍 Результат: {result} ({confidence:.1%})"
        else:
            response = "❌ Ошибка модели"

        # Обновление статистики
        with create_connection() as conn:
            conn.execute("UPDATE users SET prediction_count = prediction_count + 1 WHERE id=?", (chat_id,))

        bot.reply_to(message, response)

    except Exception as e:
        logger.error(f"Image processing error: {e}")
        bot.reply_to(message, "❌ Ошибка обработки изображения")


if __name__ == '__main__':
    init_db()

    if set_telegram_webhook():
        app.run(
            host='0.0.0.0',
            port=PORT,
            debug=False,
            use_reloader=False
        )
    else:
        logger.error("Failed to start due to webhook setup error")
