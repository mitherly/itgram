import os
import re
import uuid
import time
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from crypto_utils import generate_aes_key, encrypt_message, decrypt_message

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_for_course')
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'static/avatars'

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent', logger=False)

os.makedirs('static/wallpapers', exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# ---------- ЗАЩИТНЫЕ ЗАГОЛОВКИ ----------
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers[
        'Content-Security-Policy'] = "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; connect-src * ws: wss:"
    return response


# ---------- ЗАЩИТА ОТ БРУТФОРСА ----------
login_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
BLOCK_TIME = 300


def is_blocked(ip):
    now = time.time()
    attempts = login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < BLOCK_TIME]
    login_attempts[ip] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def record_attempt(ip):
    login_attempts[ip].append(time.time())


# ---------- ЗАЩИТА ОТ XSS ----------
def sanitize_input(text):
    if not text:
        return text
    text = re.sub(r'<[^>]*>', '', text)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
    return text


# ---------- ВАЛИДАЦИЯ ПАРОЛЯ ----------
def validate_password(password):
    if len(password) < 6:
        return False, "Пароль должен быть минимум 6 символов"
    if not re.search(r'[A-ZА-ЯЁ]', password):
        return False, "Пароль должен содержать хотя бы одну заглавную букву"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\'\"\\|,.<>\/?`~]', password):
        return False, "Пароль должен содержать хотя бы один спецсимвол"
    return True, ""


# ---------- МОДЕЛИ ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    chat_key = db.Column(db.LargeBinary, nullable=False)
    avatar = db.Column(db.String(256), default='default.png')
    bio = db.Column(db.String(200), default='')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    read = db.Column(db.Boolean, default=False)


class FileMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_name = db.Column(db.String(256), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    read = db.Column(db.Boolean, default=False)


class StickerPack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class Sticker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pack_id = db.Column(db.Integer, db.ForeignKey('sticker_pack.id'), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    emoji = db.Column(db.String(10), default='⭐')


with app.app_context():
    db.create_all()


# ---------- АВТОРИЗАЦИЯ ----------
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        password = request.form['password']

        if len(username) < 3 or len(username) > 20:
            return render_template('register.html', error='Ник от 3 до 20 символов')

        valid, msg = validate_password(password)
        if not valid:
            return render_template('register.html', error=msg)

        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Ник уже занят')

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            chat_key=generate_aes_key()
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr

        if is_blocked(ip):
            return render_template('login.html', error='Слишком много попыток. Попробуйте позже.')

        username = sanitize_input(request.form['username'])
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_attempts.pop(ip, None)
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('chat_index'))

        record_attempt(ip)
        return render_template('login.html', error='Неверный логин или пароль')
    return render_template('login.html')


@app.route('/chat')
def chat_index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', username=session['username'])


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ---------- ПРОФИЛЬ ----------
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    return render_template('profile.html', user=user)


@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, user_id)
    if not user:
        return redirect(url_for('chat_index'))
    return render_template('profile_view.html', user=user)


@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Auth'}), 401
    user = db.session.get(User, session['user_id'])
    if 'bio' in request.form:
        user.bio = sanitize_input(request.form['bio'])[:200]
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file.filename and file.filename != '':
            ext = file.filename.rsplit('.', 1)[-1].lower()
            if ext not in ['jpg', 'jpeg', 'png', 'webp', 'gif']:
                return jsonify({'error': 'Invalid format'}), 400
            if user.avatar != 'default.png':
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], user.avatar)
                if os.path.exists(old_path):
                    os.remove(old_path)
            filename = f"user_{user.id}_{uuid.uuid4().hex[:8]}.{ext}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.avatar = filename
    db.session.commit()
    return jsonify({'status': 'ok', 'avatar': user.avatar, 'bio': user.bio})


@app.route('/api/user/<int:user_id>')
def get_user_info(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Auth'}), 401
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'id': user.id, 'username': user.username, 'avatar': user.avatar, 'bio': user.bio})


@app.route('/static/avatars/<path:filename>')
def serve_avatar(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ---------- ПОИСК ----------
@app.route('/api/search')
def search_users():
    if 'user_id' not in session:
        return jsonify([])
    q = sanitize_input(request.args.get('q', ''))
    if len(q) < 1:
        return jsonify([])
    users = User.query.filter(User.username.ilike(f'%{q}%'), User.username != session['username']).limit(20).all()
    return jsonify([{'id': u.id, 'username': u.username, 'avatar': u.avatar, 'bio': u.bio} for u in users])


# ---------- ИСТОРИЯ СООБЩЕНИЙ ----------
@app.route('/api/messages/<int:receiver_id>')
def get_message_history(receiver_id):
    if 'user_id' not in session:
        return jsonify([])
    current_user_id = session['user_id']
    messages = Message.query.filter(
        ((Message.sender_id == current_user_id) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user_id))
    ).order_by(Message.timestamp).all()
    file_messages = FileMessage.query.filter(
        ((FileMessage.sender_id == current_user_id) & (FileMessage.receiver_id == receiver_id)) |
        ((FileMessage.sender_id == receiver_id) & (FileMessage.receiver_id == current_user_id))
    ).order_by(FileMessage.timestamp).all()
    result = []
    for msg in messages:
        if msg.receiver_id == current_user_id and not msg.read:
            msg.read = True
        if msg.receiver_id == current_user_id:
            decrypt_key = db.session.get(User, current_user_id).chat_key
        else:
            decrypt_key = db.session.get(User, msg.receiver_id).chat_key
        try:
            decrypted = decrypt_message(msg.encrypted_content, decrypt_key)
            if isinstance(decrypted, bytes):
                decrypted = decrypted.decode('utf-8')
        except:
            decrypted = "[Ошибка расшифровки]"
        sender = db.session.get(User, msg.sender_id)
        result.append({'type': 'text', 'id': msg.id, 'sender_id': msg.sender_id,
                       'sender_username': sender.username if sender else 'Unknown',
                       'sender_avatar': sender.avatar if sender else 'default.png', 'text': decrypted,
                       'timestamp': msg.timestamp.strftime('%H:%M') if msg.timestamp else '', 'read': msg.read})
    for msg in file_messages:
        if msg.receiver_id == current_user_id and not msg.read:
            msg.read = True
        sender = db.session.get(User, msg.sender_id)
        is_image = msg.file_type and msg.file_type.startswith('image/')
        result.append({'type': 'file', 'id': msg.id, 'sender_id': msg.sender_id,
                       'sender_username': sender.username if sender else 'Unknown',
                       'sender_avatar': sender.avatar if sender else 'default.png', 'file_name': msg.file_name,
                       'file_type': msg.file_type or 'application/octet-stream', 'is_image': is_image,
                       'timestamp': msg.timestamp.strftime('%H:%M') if msg.timestamp else '', 'read': msg.read,
                       'file_url': f'/api/file/{msg.id}'})
    db.session.commit()
    result.sort(key=lambda x: (x.get('timestamp', ''), x.get('id', 0)))
    return jsonify(result)


# ---------- ФАЙЛЫ ----------
@app.route('/api/file/<int:file_id>')
def get_file(file_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Auth required'}), 401
    current_user_id = session['user_id']
    msg = db.session.get(FileMessage, file_id)
    if not msg:
        return jsonify({'error': 'File not found'}), 404
    if msg.receiver_id != current_user_id and msg.sender_id != current_user_id:
        return jsonify({'error': 'Access denied'}), 403
    if msg.receiver_id == current_user_id:
        user = db.session.get(User, current_user_id)
    else:
        user = db.session.get(User, msg.receiver_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    try:
        decrypted_data = decrypt_message(msg.encrypted_data, user.chat_key)
        if decrypted_data is None:
            return jsonify({'error': 'Decryption returned None'}), 500
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500
    safe_filename = msg.file_name.encode('ascii', 'ignore').decode('ascii')
    if not safe_filename:
        safe_filename = 'file'
    response = Response(decrypted_data, mimetype=msg.file_type or 'application/octet-stream')
    response.headers['Content-Disposition'] = f"inline; filename={safe_filename}"
    return response


@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Auth required'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    receiver_id = int(request.form.get('receiver_id', 0))
    if file.filename == '' or receiver_id == 0:
        return jsonify({'error': 'Invalid data'}), 400
    receiver = db.session.get(User, receiver_id)
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404
    file_data = file.read()
    original_type = file.content_type or 'application/octet-stream'
    safe_filename = sanitize_input(file.filename)
    if not all(ord(c) < 128 for c in safe_filename):
        ext = safe_filename.rsplit('.', 1)[-1] if '.' in safe_filename else 'jpg'
        name_part = re.sub(r'[^a-zA-Z0-9]', '_', safe_filename.rsplit('.', 1)[0]) if '.' in safe_filename else 'file'
        safe_filename = f'{name_part[:20]}.{ext}'
    encrypted = encrypt_message(file_data, receiver.chat_key)
    msg = FileMessage(sender_id=session['user_id'], receiver_id=receiver_id, file_name=safe_filename,
                      file_type=original_type, encrypted_data=encrypted)
    db.session.add(msg)
    db.session.commit()
    sender = db.session.get(User, session['user_id'])
    room = get_room_name(session['user_id'], receiver_id)
    socketio.emit('file_received',
                  {'type': 'file', 'id': msg.id, 'sender_id': session['user_id'], 'sender_username': sender.username,
                   'sender_avatar': sender.avatar, 'file_name': safe_filename, 'file_type': original_type,
                   'is_image': original_type.startswith('image/'),
                   'timestamp': msg.timestamp.strftime('%H:%M') if msg.timestamp else '', 'read': False,
                   'file_url': f'/api/file/{msg.id}'}, to=room)
    return jsonify({'status': 'ok', 'message_id': msg.id})


# ---------- УДАЛЕНИЕ ----------
@app.route('/api/message/<int:message_id>/delete', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Auth required'}), 401
    msg = db.session.get(Message, message_id)
    if msg and msg.sender_id == session['user_id']:
        room = get_room_name(msg.sender_id, msg.receiver_id)
        socketio.emit('message_deleted', {'message_id': message_id, 'type': 'text'}, to=room)
        db.session.delete(msg)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/file/<int:file_id>/delete', methods=['POST'])
def delete_file_message(file_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Auth required'}), 401
    msg = db.session.get(FileMessage, file_id)
    if msg and msg.sender_id == session['user_id']:
        room = get_room_name(msg.sender_id, msg.receiver_id)
        socketio.emit('message_deleted', {'message_id': file_id, 'type': 'file'}, to=room)
        db.session.delete(msg)
        db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'error': 'Not found'}), 404


# ---------- СТИКЕРЫ ----------
@app.route('/api/stickers/packs')
def get_sticker_packs():
    packs = StickerPack.query.all()
    result = []
    for pack in packs:
        stickers = Sticker.query.filter_by(pack_id=pack.id).all()
        owner = db.session.get(User, pack.owner_id)
        result.append(
            {'id': pack.id, 'name': pack.name, 'owner': owner.username if owner else 'Unknown', 'count': len(stickers),
             'preview': f'/api/stickers/{stickers[0].id}' if stickers else None})
    return jsonify(result)


@app.route('/api/stickers/pack/<int:pack_id>')
def get_stickers_in_pack(pack_id):
    stickers = Sticker.query.filter_by(pack_id=pack_id).all()
    return jsonify([{'id': s.id, 'emoji': s.emoji, 'url': f'/api/stickers/{s.id}'} for s in stickers])


@app.route('/api/stickers/<int:sticker_id>')
def get_sticker(sticker_id):
    sticker = db.session.get(Sticker, sticker_id)
    if not sticker:
        return jsonify({'error': 'Not found'}), 404
    return Response(sticker.file_data, mimetype='image/webp')


@app.route('/api/stickers/create_pack', methods=['POST'])
def create_sticker_pack():
    if 'user_id' not in session:
        return jsonify({'error': 'Auth'}), 401
    data = request.get_json()
    name = sanitize_input(data.get('name', 'Мой стикерпак'))[:50]
    pack = StickerPack(name=name, owner_id=session['user_id'])
    db.session.add(pack)
    db.session.commit()
    return jsonify({'id': pack.id, 'name': pack.name})


@app.route('/api/stickers/add_to_pack/<int:pack_id>', methods=['POST'])
def add_sticker_to_pack(pack_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Auth'}), 401
    pack = db.session.get(StickerPack, pack_id)
    if not pack or pack.owner_id != session['user_id']:
        return jsonify({'error': 'Not your pack'}), 403
    if 'sticker' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['sticker']
    file_data = file.read()
    sticker = Sticker(pack_id=pack_id, file_data=file_data, emoji='⭐')
    db.session.add(sticker)
    db.session.commit()
    return jsonify({'id': sticker.id})


# ---------- ОБОИ ЧАТА ----------
@app.route('/api/wallpaper', methods=['POST'])
def upload_wallpaper():
    if 'user_id' not in session:
        return jsonify({'error': 'Auth'}), 401
    if 'wallpaper' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['wallpaper']
    if file.filename == '':
        return jsonify({'error': 'No file'}), 400
    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in ['jpg', 'jpeg', 'png', 'webp']:
        return jsonify({'error': 'Формат не поддерживается'}), 400
    user = db.session.get(User, session['user_id'])
    filename = f"wallpaper_{user.id}.{ext}"
    filepath = os.path.join('static/wallpapers', filename)
    file.save(filepath)
    return jsonify({'status': 'ok', 'url': f'/static/wallpapers/{filename}'})


# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
def get_room_name(user1_id, user2_id):
    return f"chat_{min(user1_id, user2_id)}_{max(user1_id, user2_id)}"


# ---------- SOCKET.IO ----------
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(f"user_{session['user_id']}")


@socketio.on('join_chat')
def handle_join_chat(data):
    room = get_room_name(session['user_id'], data['receiver_id'])
    join_room(room)


@socketio.on('send_message')
def handle_message(data):
    if 'user_id' not in session:
        return
    sender_id = session['user_id']
    receiver_id = data['receiver_id']
    text = sanitize_input(data['message'])
    if not text or len(text) > 5000:
        return
    receiver = db.session.get(User, receiver_id)
    sender = db.session.get(User, sender_id)
    if not receiver or not sender:
        return
    encrypted = encrypt_message(text, receiver.chat_key)
    msg = Message(sender_id=sender_id, receiver_id=receiver_id, encrypted_content=encrypted)
    db.session.add(msg)
    db.session.commit()
    try:
        decrypted_text = decrypt_message(encrypted, receiver.chat_key)
        if isinstance(decrypted_text, bytes):
            decrypted_text = decrypted_text.decode('utf-8')
    except:
        decrypted_text = "[Ошибка расшифровки]"
    room = get_room_name(sender_id, receiver_id)
    emit('receive_message', {'type': 'text', 'id': msg.id, 'sender_id': sender_id, 'sender_username': sender.username,
                             'sender_avatar': sender.avatar, 'text': decrypted_text,
                             'timestamp': msg.timestamp.strftime('%H:%M') if msg.timestamp else '', 'read': False},
         to=room)


@socketio.on('typing')
def handle_typing(data):
    if 'user_id' not in session:
        return
    room = get_room_name(session['user_id'], data['receiver_id'])
    emit('user_typing', {'sender_id': session['user_id'], 'is_typing': data['is_typing']}, to=room, include_self=False)


@socketio.on('send_sticker')
def handle_sticker(data):
    if 'user_id' not in session:
        return
    sender = db.session.get(User, session['user_id'])
    room = get_room_name(session['user_id'], data['receiver_id'])
    from datetime import datetime
    emit('receive_sticker',
         {'sender_id': session['user_id'], 'sender_username': sender.username, 'sender_avatar': sender.avatar,
          'sticker_url': f"/api/stickers/{data['sticker_id']}", 'timestamp': datetime.now().strftime('%H:%M')}, to=room)


@socketio.on('message_read')
def handle_message_read(data):
    if 'user_id' not in session:
        return
    msg_id = data['message_id']
    msg_type = data.get('type', 'text')
    msg = db.session.get(Message, msg_id) if msg_type == 'text' else db.session.get(FileMessage, msg_id)
    if msg and msg.sender_id != session['user_id']:
        msg.read = True
        db.session.commit()
        room = get_room_name(session['user_id'], msg.sender_id)
        emit('message_read_by', {'message_id': msg_id, 'type': msg_type}, to=room)


@socketio.on('disconnect')
def handle_disconnect():
    pass


if __name__ == '__main__':
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)