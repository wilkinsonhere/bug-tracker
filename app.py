import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'QWertyNine123!'  # Замените на безопасный ключ
app.config['UPLOAD_FOLDER'] = 'uploads'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Инициализация базы данных
def init_db():
    with sqlite3.connect('bugs.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Игрок',
            is_admin BOOLEAN NOT NULL DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS bug_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_number TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            steps TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Открыт',
            priority TEXT NOT NULL DEFAULT 'Средний',
            category TEXT NOT NULL DEFAULT 'Общее',
            created_at TIMESTAMP NOT NULL,
            last_updated_at TIMESTAMP,
            last_updated_by INTEGER,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (last_updated_by) REFERENCES users (id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bug_id INTEGER,
            user_id INTEGER,
            content TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            FOREIGN KEY (bug_id) REFERENCES bug_reports (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        # Создаем админа по умолчанию
        c.execute('SELECT * FROM users WHERE username = ?', ('thegr8moore',))
        if not c.fetchone():
            c.execute('INSERT INTO users (username, password, is_admin, role) VALUES (?, ?, ?, ?)',
                     ('thegr8moore', generate_password_hash('admin123'), 1, 'Админ'))
        conn.commit()

# Модель пользователя
class User(UserMixin):
    def __init__(self, id, username, role, is_admin):
        self.id = id
        self.username = username
        self.role = role
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect('bugs.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id, username, role, is_admin FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        if user:
            return User(user[0], user[1], user[2], user[3])
        return None

# Инициализация базы данных
init_db()

# Главная страница
@app.route('/')
def index():
    return render_template('index.html')

# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('bugs.db') as conn:
            c = conn.cursor()
            c.execute('SELECT id, username, password, role, is_admin FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            if user and check_password_hash(user[2], password):
                login_user(User(user[0], user[1], user[3], user[4]))
                return redirect(url_for('index'))
            flash('Неверный логин или пароль')
    return render_template('login.html')

# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('bugs.db') as conn:
            c = conn.cursor()
            try:
                c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                         (username, generate_password_hash(password), 'Игрок'))
                conn.commit()
                flash('Регистрация успешна! Пожалуйста, войдите.')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Пользователь с таким именем уже существует')
    return render_template('register.html')

# Выход
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Создание баг-репорта
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        steps = request.form['steps']
        priority = request.form['priority']
        category = request.form['category']
        with sqlite3.connect('bugs.db') as conn:
            c = conn.cursor()
            # Генерация номера тикета (например, TICK-2025-05-0001)
            year_month = datetime.now().strftime('%Y-%m')
            c.execute('SELECT COUNT(*) FROM bug_reports WHERE ticket_number LIKE ?', (f'TICK-{year_month}-%',))
            count = c.fetchone()[0] + 1
            ticket_number = f'TICK-{year_month}-{count:04d}'
            c.execute('INSERT INTO bug_reports (ticket_number, title, description, steps, priority, category, created_at, user_id, last_updated_at, last_updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                     (ticket_number, title, description, steps, priority, category, datetime.now().isoformat(), current_user.id, datetime.now().isoformat(), current_user.id))
            conn.commit()
            flash('Баг-репорт успешно создан!')
            return redirect(url_for('bug_list'))
    return render_template('report.html')

# Список всех багов с фильтрами и поиском
@app.route('/bugs')
def bug_list():
    with sqlite3.connect('bugs.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        query = 'SELECT br.*, u.username, u.role FROM bug_reports br JOIN users u ON br.user_id = u.id'
        params = []
        search = request.args.get('search', '')
        status = request.args.get('status', '')
        role = request.args.get('role', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')

        conditions = []
        if search:
            conditions.append("br.title LIKE ? OR br.description LIKE ? OR br.ticket_number LIKE ?")
            params.extend(['%' + search + '%', '%' + search + '%', '%' + search + '%'])
        if status:
            conditions.append("br.status = ?")
            params.append(status)
        if role:
            conditions.append("u.role = ?")
            params.append(role)
        if date_from:
            conditions.append("br.created_at >= ?")
            params.append(date_from + ' 00:00:00')
        if date_to:
            conditions.append("br.created_at <= ?")
            params.append(date_to + ' 23:59:59')

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY br.created_at DESC"
        c.execute(query, params)
        bugs = c.fetchall()
        bugs = [dict(bug, created_at=datetime.fromisoformat(bug['created_at']), last_updated_at=datetime.fromisoformat(bug['last_updated_at']) if bug['last_updated_at'] else None) for bug in bugs]
    return render_template('bug_list.html', bugs=bugs, search=search, status=status, role=role, date_from=date_from, date_to=date_to)

# Детали бага и комментарии
@app.route('/bug/<int:bug_id>', methods=['GET', 'POST'])
@login_required
def bug_detail(bug_id):
    with sqlite3.connect('bugs.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT br.*, u.username, u.role FROM bug_reports br JOIN users u ON br.user_id = u.id WHERE br.id = ?', (bug_id,))
        bug = c.fetchone()
        if not bug:
            flash('Баг-репорт не найден')
            return redirect(url_for('bug_list'))
        c.execute('SELECT c.*, u.username, u.role FROM comments c JOIN users u ON c.user_id = u.id WHERE c.bug_id = ? ORDER BY c.created_at', (bug_id,))
        comments = c.fetchall()
        last_updated_user = None
        if bug['last_updated_by']:
            c.execute('SELECT u.username, u.role FROM users u WHERE u.id = ?', (bug['last_updated_by'],))
            last_updated_user = c.fetchone()
        
        if request.method == 'POST':
            if 'comment' in request.form:
                content = request.form['comment']
                c.execute('INSERT INTO comments (bug_id, user_id, content, created_at) VALUES (?, ?, ?, ?)',
                         (bug_id, current_user.id, content, datetime.now().isoformat()))
                c.execute('UPDATE bug_reports SET last_updated_at = ?, last_updated_by = ? WHERE id = ?',
                         (datetime.now().isoformat(), current_user.id, bug_id))
                conn.commit()
                flash('Комментарий добавлен!')
            elif 'status' in request.form and current_user.is_admin:
                status = request.form['status']
                c.execute('UPDATE bug_reports SET status = ?, last_updated_at = ?, last_updated_by = ? WHERE id = ?',
                         (status, datetime.now().isoformat(), current_user.id, bug_id))
                conn.commit()
                flash('Статус обновлен!')
            elif 'edit_comment_id' in request.form and current_user.is_admin:
                comment_id = request.form['edit_comment_id']
                new_content = request.form['edit_content']
                c.execute('UPDATE comments SET content = ?, created_at = ? WHERE id = ? AND user_id = ?',
                         (new_content, datetime.now().isoformat(), comment_id, current_user.id))
                conn.commit()
                flash('Комментарий отредактирован!')
            elif 'delete_comment_id' in request.form and current_user.is_admin:
                comment_id = request.form['delete_comment_id']
                c.execute('DELETE FROM comments WHERE id = ? AND user_id = ?', (comment_id, current_user.id))
                conn.commit()
                flash('Комментарий удален!')
            return redirect(url_for('bug_detail', bug_id=bug_id))

    bug = dict(bug, created_at=datetime.fromisoformat(bug['created_at']), last_updated_at=datetime.fromisoformat(bug['last_updated_at']) if bug['last_updated_at'] else None)
    comments = [dict(comment, created_at=datetime.fromisoformat(comment['created_at'])) for comment in comments]
    last_updated_user = dict(last_updated_user) if last_updated_user else None
    
    return render_template('bug_detail.html', bug=bug, comments=comments, last_updated_user=last_updated_user)

# Админ-панель
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('Доступ запрещен')
        return redirect(url_for('index'))
    with sqlite3.connect('bugs.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if request.method == 'POST':
            user_id = request.form['user_id']
            new_role = request.form['role']
            c.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
            conn.commit()
            flash(f'Роль пользователя обновлена на {new_role}')
        c.execute('SELECT br.*, u.username, u.role FROM bug_reports br JOIN users u ON br.user_id = u.id ORDER BY br.created_at DESC')
        bugs = c.fetchall()
        c.execute('SELECT id, username, role FROM users')
        users = c.fetchall()
        bugs = [dict(bug, created_at=datetime.fromisoformat(bug['created_at']), last_updated_at=datetime.fromisoformat(bug['last_updated_at']) if bug['last_updated_at'] else None) for bug in bugs]
    return render_template('admin.html', bugs=bugs, users=users)

@app.route('/update_bug', methods=['POST'])
@login_required
def update_bug():
    if not current_user.is_admin:
        flash('Доступ запрещен')
        return redirect(url_for('bug_list'))
    bug_id = request.form['bug_id']
    priority = request.form['priority']
    category = request.form['category']
    with sqlite3.connect('bugs.db') as conn:
        c = conn.cursor()
        c.execute('UPDATE bug_reports SET priority = ?, category = ?, last_updated_at = ?, last_updated_by = ? WHERE id = ?',
                 (priority, category, datetime.now().isoformat(), current_user.id, bug_id))
        conn.commit()
        flash('Приоритет и категория обновлены!')
    return redirect(url_for('bug_detail', bug_id=bug_id))

if __name__ == '__main__':
    app.run(debug=False)