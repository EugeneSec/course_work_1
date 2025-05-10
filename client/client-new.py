import os
import json
import hashlib
import time
import socket
import ssl
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox

CONFIG_FILE = "config.json"

def load_config():
    """Загружает конфиг или создает новый через GUI"""
    if not os.path.exists(CONFIG_FILE):
        return setup_config_gui()
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def setup_config_gui():
    """GUI для первичной настройки"""
    root = tk.Tk()
    root.title("Настройка мониторинга файлов")
    
    # Переменные для хранения данных
    server_ip = tk.StringVar(value="127.0.0.1")
    server_port = tk.StringVar(value="8443")
    username = tk.StringVar(value="client1")
    password = tk.StringVar()
    scan_interval = tk.StringVar(value="60")
    monitored_paths = []

    def add_path():
        path = filedialog.askdirectory()
        if path:
            monitored_paths.append(path)
            path_listbox.insert(tk.END, path)

    def save_config():
        if not monitored_paths:
            messagebox.showerror("Ошибка", "Добавьте хотя бы одну папку для мониторинга")
            return
        config = {
            "server_ip": server_ip.get(),
            "server_port": int(server_port.get()),
            "username": username.get(),
            "password": password.get(),
            "scan_interval": int(scan_interval.get()),
            "monitored_paths": monitored_paths
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        messagebox.showinfo("Успех", "Конфигурация сохранена!")
        root.destroy()

    # Элементы интерфейса
    tk.Label(root, text="IP сервера:").grid(row=0, column=0, sticky="w")
    tk.Entry(root, textvariable=server_ip).grid(row=0, column=1)

    tk.Label(root, text="Порт сервера:").grid(row=1, column=0, sticky="w")
    tk.Entry(root, textvariable=server_port).grid(row=1, column=1)

    tk.Label(root, text="Логин:").grid(row=2, column=0, sticky="w")
    tk.Entry(root, textvariable=username).grid(row=2, column=1)

    tk.Label(root, text="Пароль:").grid(row=3, column=0, sticky="w")
    tk.Entry(root, textvariable=password, show="*").grid(row=3, column=1)

    tk.Label(root, text="Интервал сканирования (сек):").grid(row=4, column=0, sticky="w")
    tk.Entry(root, textvariable=scan_interval).grid(row=4, column=1)

    tk.Label(root, text="Мониторируемые папки:").grid(row=5, column=0, sticky="w")
    path_listbox = tk.Listbox(root, height=4)
    path_listbox.grid(row=6, column=0, columnspan=2, sticky="ew")
    tk.Button(root, text="Добавить папку", command=add_path).grid(row=7, column=0)

    tk.Button(root, text="Сохранить", command=save_config).grid(row=8, column=1, sticky="e")

    root.mainloop()
    return load_config()  # Перезагружаем конфиг после сохранения

def get_file_metadata(filepath):
    """Собирает метаданные файла"""
    if not os.path.exists(filepath):
        return None
    stat = os.stat(filepath)
    created_dt = datetime.fromtimestamp(stat.st_ctime)
    modified_dt = datetime.fromtimestamp(stat.st_mtime)
    metadata = {
        "path": filepath,
        "size": stat.st_size,
        "created": created_dt.isoformat(),
        "modified": modified_dt.isoformat(),
        "hash": ""
    }
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    metadata["hash"] = sha256.hexdigest()
    return metadata

def scan_files(paths):
    """Сканирует файлы в указанных путях"""
    files_metadata = []
    for path in paths:
        if os.path.isfile(path):
            metadata = get_file_metadata(path)
            if metadata:
                files_metadata.append(metadata)
        else:
            for root, _, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    metadata = get_file_metadata(filepath)
                    if metadata:
                        files_metadata.append(metadata)
    return files_metadata

def send_data_to_server(config, data):
    """Отправляет данные на сервер"""
    client_key = 'client.key'
    client_cert = 'client.crt'
    server_cert = 'server.crt'
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT, cafile=server_cert)
    context.load_verify_locations(cafile=server_cert)
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    # Явное указание поддерживаемых протоколов
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    
    try:
        with socket.create_connection((config["server_ip"], config["server_port"])) as sock:
            with context.wrap_socket(
                sock,
                server_side=False,
                server_hostname=config["server_ip"]
            ) as secure_sock:
                # Формируем данные для отправки
                print("Данные формируются для отправки")
                auth_data = {
                    "username": config["username"],
                    "password": config["password"],
                    "files": data
                }
                json_data = json.dumps(auth_data).encode()
                # Отправляем длину сообщения (4 байта)
                secure_sock.sendall(len(json_data).to_bytes(4, 'big'))
                # Отправляем данные
                secure_sock.sendall(json_data)
                print("Данные отправлены")
                # Получаем ответ
                response = secure_sock.recv(1024).decode()
                print("Server response:", response)
                secure_sock.unwrap()
                
    except ssl.SSLError as e:
        print(f"SSL Connection error: {e}")
    except Exception as e:
        print(f"Connection error: {e}")

def main():
    config = load_config()
    while True:
        files_metadata = scan_files(config["monitored_paths"])
        send_data_to_server(config, files_metadata)
        time.sleep(config["scan_interval"])

if __name__ == "__main__":
    main()
