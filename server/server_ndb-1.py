from flask import Flask, request, render_template, redirect, url_for, flash, session, abort
import ssl
import socket
import threading
import json
import hashlib
from datetime import datetime
from functools import wraps
import psycopg2
from psycopg2 import pool

app = Flask(__name__)
app.secret_key = 'super_secret_key_123!'

# Конфигурация PostgreSQL
POSTGRES_CONFIG = {
    "host": "localhost",
    "database": "file_monitor",
    "user": "postgres",
    "password": "yourpassword",
    "port": "5432"
}

# Создаем пул соединений
postgres_pool = psycopg2.pool.ThreadedConnectionPool(
    minconn=1,
    maxconn=10,
    **POSTGRES_CONFIG
)

def hash_password(password):
    """Хеширование пароля с использованием SHA-256"""
    if isinstance(password, str):
        password = password.encode('utf-8')
    return hashlib.sha256(password).hexdigest()
# Роли пользователей
ROLES = {
    'admin': 2,
    'user': 1
}

def init_db():
    """Инициализация базы данных"""
    conn = postgres_pool.getconn()
    try:
        print('start init db')
        cursor = conn.cursor()

        # Таблица пользователей
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            role INTEGER DEFAULT 1,
            created_at TIMESTAMP,
            last_login TIMESTAMP
        )
        """)

        # Таблица для аутентификации клиентов
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS client_auth (
            id SERIAL PRIMARY KEY,
            client_name TEXT UNIQUE,
            password_hash TEXT,
            description TEXT,
            added_by INTEGER REFERENCES users(id),
            added_at TIMESTAMP
        )
        """)

        # Таблица файлов клиентов
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients_files (
            id SERIAL PRIMARY KEY,
            client_id INTEGER REFERENCES client_auth(id),
            path TEXT,
            size BIGINT,
            created TIMESTAMP,
            modified TIMESTAMP,
            hash TEXT,
            UNIQUE(client_id, path)
        """)

        # Таблица изменений файлов
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS client_files_changes (
            id SERIAL PRIMARY KEY,
            client_id INTEGER REFERENCES client_auth(id),
            path TEXT,
            size BIGINT,
            created TIMESTAMP,
            modified TIMESTAMP,
            hash TEXT,
            change_type TEXT,
            detected_at TIMESTAMP
        )
        """)

        # Таблица логов
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id SERIAL PRIMARY KEY,
            client_id INTEGER REFERENCES client_auth(id),
            event_type TEXT,
            timestamp TIMESTAMP,
            details TEXT
        )
        """)

        # Создаём администратора по умолчанию
        cursor.execute("SELECT id FROM users WHERE username='admin'")
        if not cursor.fetchone():
            hashed_pw = hash_password(b'Ib23-5EDPopov')
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (%s, %s, %s, %s)",
                ('admin', hashed_pw, ROLES['admin'], datetime.now())
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Database initialization error: {e}")
    finally:
        postgres_pool.putconn(conn)

def log_event(client_id, event_type, details):
    conn = postgres_pool.getconn()
    try:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO logs (client_id, event_type, timestamp, details)
        VALUES (%s, %s, %s, %s)
        """, (client_id, event_type, datetime.now(), details))
        conn.commit()
    except Exception as e:
        print(f"Logging error: {e}")
    finally:
        postgres_pool.putconn(conn)


def run_server():
    # Создаем контекст с явным указанием серверного протокола
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.load_verify_locations("client.crt")
    # Настройки безопасности
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        
        sock.bind(("0.0.0.0", 8443))
        sock.listen(5)
        
        # Оборачиваем сокет в SSL
        with context.wrap_socket(
            sock,
            server_side=True,
            do_handshake_on_connect=True,
            suppress_ragged_eofs=True
        ) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    threading.Thread(
                        target=handle_client,
                        args=(conn, addr, context),
                        daemon=True
                    ).start()
                except ssl.SSLError as e:
                    print(f"SSL Error accepting connection: {e}")
                    if 'conn' in locals():
                        conn.close()

def handle_client(conn, addr, context):
    secure_conn = None
    try:
        print("connection process")
        secure_conn = conn
        length_data = secure_conn.recv(4)
        if not length_data:
            raise ValueError("Connection closed by client")
        length = int.from_bytes(length_data, 'big')
        
        data = b''
        while len(data) < length:
            chunk = secure_conn.recv(4096)
            if not chunk:
                raise ValueError("Incomplete receive")
            data += chunk
        if not data:
            raise ValueError("Empty data receive")
        data = json.loads(data.decode())
        
        # Проверка обязательных полей
        if not all(key in data for key in ['username', 'password', 'files']):
            conn.send(b'Invalid request format')
            return

        client_name = data['username']
        input_password = data['password']
        files = data['files']
        print("data received:",client_name, input_password,"start process")
        #connect to db
        db_conn = postgres_pool.getconn()
        try:
            cursor = db_conn.cursor()
            cursor.execute("SELECT id, password_hash FROM client_auth WHERE client_name=%s", (client_name,))
            client = cursor.fetchone()
            
            if not client:
                secure_conn.send(b'Client not registered')
                log_event(0, "auth_failed", f"Attempt to connect as unregistered client: {client_name}")
                return

            client_id, stored_hash = client
            if hash_password(input_password) != stored_hash:
                secure_conn.send(b'Authentication failed')
                log_event(client_id, "auth_failed", "Invalid client password")
                return

            secure_conn.send(b'Authentication successful')

            # Обработка файлов
            for file in files:
                cursor.execute("SELECT hash FROM clients_files WHERE client_id=%s AND path=%s", (client_id, file["path"]))
                existing = cursor.fetchone()
                
                if not existing:
                    cursor.execute("""
                    INSERT INTO client_files_changes 
                    (client_id, path, size, created, modified, hash, change_type, detected_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        client_id, file["path"], file["size"],
                        file["created"], file["modified"], file["hash"],
                        "new_file", datetime.now()
                    ))
                    log_event(client_id, "file_added", f'New file: {file["path"]}')
                elif existing[0] != file["hash"]:
                    cursor.execute("""
                    INSERT INTO client_files_changes 
                    (client_id, path, size, created, modified, hash, change_type, detected_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        client_id, file["path"], file["size"],
                        file["created"], file["modified"], file["hash"],
                        "modified", datetime.now()
                    ))
                    log_event(client_id, "file_modified", f"Changed: {file['path']}")

            # Обновляем основную таблицу файлов
            cursor.execute("DELETE FROM clients_files WHERE client_id=%s", (client_id,))
            for file in files:
                cursor.execute("""
                INSERT INTO clients_files 
                (client_id, path, size, created, modified, hash)
                VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    client_id, file["path"], file["size"],
                    file["created"], file["modified"], file["hash"]
                ))
            db_conn.commit()
        except Exception as e:
            db_conn.rollback()
            print(f"Database error in handle_client: {e}")
        finally:
            postgres_pool.putconn(db_conn)
    except Exception as e:
        print(f"Error in handle_client: {e}")
    finally:
        if secure_conn:
            try:
                secure_conn.unwrap()
            except:
                pass
            secure_conn.close()

def login_required(role="user"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login', next=request.url))
            
            conn = postgres_pool.getconn()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT role FROM users WHERE id=%s", (session['user_id'],))
                user_role = cursor.fetchone()[0]
                
                if user_role < ROLES.get(role, 1):
                    abort(403)
                return f(*args, **kwargs)
            except Exception as e:
                print(f"Database error in login_required: {e}")
                abort(500)
            finally:
                postgres_pool.putconn(conn)
        return decorated_function
    return decorator

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Форма входа в систему"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = postgres_pool.getconn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, password_hash, role FROM users WHERE username=%s",
                (username,)
            )
            user = cursor.fetchone()
            
            if user and hash_password(password) == user[1]:
                session['user_id'] = user[0]
                session['user_role'] = user[2]
                session['username'] = username
                
                # Обновляем время последнего входа
                cursor.execute(
                    "UPDATE users SET last_login=%s WHERE id=%s",
                    (datetime.now(), user[0]))
                conn.commit()
                
                next_page = request.args.get('next') or url_for('dashboard')
                return redirect(next_page)
            
            flash("Неверное имя пользователя или пароль")
        except Exception as e:
            print(f"Database error in login: {e}")
            flash("Ошибка при входе в систему")
        finally:
            postgres_pool.putconn(conn)
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Выход из системы"""
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required()
def dashboard():
    """Главная панель мониторинга"""
    conn = postgres_pool.getconn()
    try:
        cursor = conn.cursor()
        
        # Получаем список клиентов для мониторинга
        cursor.execute("""
        SELECT ca.id, ca.client_name, ca.description, u.username 
        FROM client_auth ca
        JOIN users u ON ca.added_by = u.id
        """)
        clients = cursor.fetchall()
        
        # Получаем последние события
        cursor.execute("""
        SELECT l.timestamp, l.event_type, l.details, u.username 
        FROM logs l
        LEFT JOIN users u ON l.client_id = u.id
        ORDER BY l.timestamp DESC LIMIT 50
        """)
        logs = cursor.fetchall()
        
        return render_template('dashboard.html', 
                           clients=clients,
                           logs=logs,
                           user_role=session.get('user_role'))
    except Exception as e:
        print(f"Database error in dashboard: {e}")
        abort(500)
    finally:
        postgres_pool.putconn(conn)


@app.route('/admin/clients', methods=['GET', 'POST'])
@login_required(role="admin")
def client_management():
    """Управление клиентами (добавление/просмотр)"""
    if request.method == 'POST':
        client_name = request.form['client_name']
        password = request.form['password']
        description = request.form.get('description', '')

        conn = postgres_pool.getconn()
        try:
            hashed_pw = hash_password(password)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO client_auth (client_name, password_hash, description, added_by, added_at) VALUES (%s, %s, %s, %s, %s)",
                (client_name, hashed_pw, description, session['user_id'], datetime.now())
            )
            conn.commit()
            flash(f"Клиент {client_name} успешно добавлен", 'success')
        except psycopg2.IntegrityError:
            conn.rollback()
            flash(f"Клиент {client_name} уже существует", 'error')
        except Exception as e:
            conn.rollback()
            flash(f"Ошибка при добавлении клиента: {str(e)}", 'error')
        finally:
            postgres_pool.putconn(conn)

    # Получаем список всех клиентов
    conn = postgres_pool.getconn()
    try:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT ca.id, ca.client_name, ca.description, u.username, ca.added_at 
        FROM client_auth ca
        JOIN users u ON ca.added_by = u.id
        """)
        clients = cursor.fetchall()
    except Exception as e:
        print(f"Database error in client_management: {e}")
        clients = []
    finally:
        postgres_pool.putconn(conn)

    return render_template('admin/clients.html', clients=clients)

@app.route('/admin/users')
@login_required(role="admin")
def user_management():
    """Управление пользователями (только для админа)"""
    conn = postgres_pool.getconn()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, last_login FROM users")
        users = cursor.fetchall()
    except Exception as e:
        print(f"Database error in user_management: {e}")
        users = []
    finally:
        postgres_pool.putconn(conn)
    
    return render_template('admin/users.html', 
                         users=users,
                         roles=ROLES)

@app.route('/admin/add_user', methods=['POST'])
@login_required(role="admin")
def add_user():
    """Добавление нового пользователя"""
    username = request.form['username']
    password = request.form['password']
    role = request.form.get('role', 'user')
    
    conn = postgres_pool.getconn()
    try:
        hashed_pw = hash_password(password)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (%s, %s, %s, %s)",
            (username, hashed_pw, ROLES.get(role, 1), datetime.now())
        )
        conn.commit()
        flash(f"Пользователь {username} успешно добавлен", 'success')
    except psycopg2.IntegrityError:
        conn.rollback()
        flash(f"Пользователь {username} уже существует", 'error')
    except Exception as e:
        conn.rollback()
        flash(f"Ошибка при добавлении пользователя: {str(e)}", 'error')
    finally:
        postgres_pool.putconn(conn)
    
    return redirect(url_for('user_management'))

@app.route("/client/<int:client_id>")
@login_required()
def client_files(client_id):
    conn = postgres_pool.getconn()
    try:
        cursor = conn.cursor()

        # Основные файлы
        cursor.execute("""
        SELECT path, size, created, modified, hash 
        FROM clients_files 
        WHERE client_id=%s
        """, (client_id,))
        files = cursor.fetchall()

        # Изменения
        cursor.execute("""
        SELECT path, change_type, detected_at 
        FROM client_files_changes 
        WHERE client_id=%s
        ORDER BY detected_at DESC
        """, (client_id,))
        changes = cursor.fetchall()

        # Логи
        cursor.execute("""
        SELECT event_type, timestamp, details 
        FROM logs 
        WHERE client_id=%s
        ORDER BY timestamp DESC
        """, (client_id,))
        logs = cursor.fetchall()

    except Exception as e:
        print(f"Database error in client_files: {e}")
        files, changes, logs = [], [], []
    finally:
        postgres_pool.putconn(conn)

    return render_template(
        "client.html",
        client_id=client_id,
        files=files,
        changes=changes,
        logs=logs
    )

if __name__ == '__main__':
    try:
        print(init_db)
        init_db()
    except Exception as e:
        print(f'Error in initialization DB')
    # Запускаем сервер в отдельном потоке
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    # Запускаем веб-интерфейс
    app.run(host="0.0.0.0", port=5000)
