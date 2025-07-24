import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
import requests
import hashlib
import hmac
import time
from datetime import datetime, timedelta
import uuid
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

# Конфигурация приложения
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'fallback-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///dating_app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16777216))
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'static/uploads')

# Создание приложения
app = Flask(__name__)
app.config.from_object(Config)

# Инициализация расширений
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Получение переменных окружения
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
TELEGRAM_BOT_USERNAME = os.environ.get('TELEGRAM_BOT_USERNAME')
ADMIN_TELEGRAM_ID = os.environ.get('ADMIN_TELEGRAM_ID')

# Модели базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room = db.Column(db.String(100), nullable=False, default='general')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Функции помощники
def verify_telegram_auth(auth_data):
    """Проверка подлинности данных от Telegram"""
    if not TELEGRAM_BOT_TOKEN:
        return False

    # Создаем копию данных, чтобы не изменять оригинал
    auth_data_copy = auth_data.copy()
    check_hash = auth_data_copy.pop('hash', '')

    # Проверяем время авторизации (не более 5 минут назад)
    auth_date = int(auth_data_copy.get('auth_date', 0))
    if abs(time.time() - auth_date) > 300:  # 5 минут
        return False

    # Создаем строку для проверки подписи
    data_check_string = '\n'.join([f"{k}={v}" for k, v in sorted(auth_data_copy.items())])
    secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode()).digest()
    calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    return calculated_hash == check_hash

def allowed_file(filename):
    """Проверка разрешенных типов файлов"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Маршруты приложения
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Обновляем время последнего посещения
    user.last_seen = datetime.utcnow()
    db.session.commit()

    return render_template('index.html', user=user)

@app.route('/login')
def login():
    bot_username = os.environ.get('TELEGRAM_BOT_USERNAME')
    return render_template('login.html', bot_username=bot_username)

@app.route('/auth/telegram', methods=['GET', 'POST'])
def telegram_auth():
    try:
        # Получаем данные в зависимости от метода запроса
        if request.method == 'POST' and request.is_json:
            auth_data = request.get_json()
        else:
            auth_data = request.args.to_dict()

        # Проверяем подлинность данных
        if not verify_telegram_auth(auth_data):
            return jsonify({'error': 'Invalid authentication data'}), 400

        telegram_id = str(auth_data['id'])
        user = User.query.filter_by(telegram_id=telegram_id).first()

        if not user:
            # Создаем нового пользователя
            is_admin = telegram_id == ADMIN_TELEGRAM_ID
            user = User(
                telegram_id=telegram_id,
                username=auth_data.get('username', ''),
                first_name=auth_data.get('first_name', ''),
                last_name=auth_data.get('last_name', ''),
                is_admin=is_admin
            )
            db.session.add(user)
            db.session.commit()

        # Сохраняем пользователя в сессии
        session['user_id'] = user.id
        session['telegram_id'] = user.telegram_id

        # Обновляем время последнего посещения
        user.last_seen = datetime.utcnow()
        db.session.commit()

        # Перенаправляем на главную страницу
        return redirect(url_for('index'))

    except Exception as e:
        print(f"Auth error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    # Получаем последние сообщения
    messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
    messages.reverse()  # Показываем в хронологическом порядке

    return render_template('chat.html', user=user, messages=messages)

@app.route('/announcements')
def announcements():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    announcements = Announcement.query.filter_by(is_active=True).order_by(Announcement.created_at.desc()).all()
    return render_template('announcements.html', user=user, announcements=announcements)

@app.route('/stories')
def stories():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    # Получаем активные истории, которые еще не истекли
    active_stories = Story.query.filter(
        Story.is_active == True,
        Story.expires_at > datetime.utcnow()
    ).order_by(Story.created_at.desc()).all()

    return render_template('stories.html', user=user, stories=active_stories)

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

    return render_template('admin.html', user=user)

@app.route('/admin/announcement', methods=['POST'])
def create_announcement():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    announcement = Announcement(
        title=data['title'],
        content=data['content'],
        author_id=user.id
    )
    db.session.add(announcement)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/admin/story', methods=['POST'])
def create_story():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    expires_at = datetime.utcnow() + timedelta(hours=24)  # История активна 24 часа

    story = Story(
        title=data['title'],
        content=data['content'],
        image_url=data.get('image_url', ''),
        author_id=user.id,
        expires_at=expires_at
    )
    db.session.add(story)
    db.session.commit()

    return jsonify({'success': True})

# WebSocket события для чата
@socketio.on('join')
def on_join(data):
    if 'user_id' not in session:
        return

    room = data.get('room', 'general')
    join_room(room)

    user = User.query.get(session['user_id'])
    if user:
        emit('status', {'msg': f'{user.first_name} joined the chat'}, room=room)

@socketio.on('leave')
def on_leave(data):
    if 'user_id' not in session:
        return

    room = data.get('room', 'general')
    leave_room(room)

    user = User.query.get(session['user_id'])
    if user:
        emit('status', {'msg': f'{user.first_name} left the chat'}, room=room)

@socketio.on('message')
def handle_message(data):
    if 'user_id' not in session:
        return

    user = User.query.get(session['user_id'])
    if not user:
        return

    room = data.get('room', 'general')
    message_content = data.get('message', '')

    if message_content.strip():
        # Сохраняем сообщение в базу данных
        message = Message(
            content=message_content,
            sender_id=user.id,
            room=room
        )
        db.session.add(message)
        db.session.commit()

        # Отправляем сообщение всем в комнате
        emit('message', {
            'message': message_content,
            'username': user.first_name,
            'timestamp': message.timestamp.strftime('%H:%M')
        }, room=room)

# Создание таблиц базы данных (ВАЖНО: в конце файла!)
with app.app_context():
    db.create_all()

    # Проверяем, есть ли админ, если нет - создаем
    if ADMIN_TELEGRAM_ID:
        admin_user = User.query.filter_by(telegram_id=ADMIN_TELEGRAM_ID).first()
        if not admin_user:
            print(f"Admin user with Telegram ID {ADMIN_TELEGRAM_ID} will be created on first login")

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
