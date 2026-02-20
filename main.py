import sys

from PySide6.QtWidgets import (
    QApplication, QPushButton, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QWidget, QLabel, QMainWindow, QFileDialog,
)
from PySide6.QtCore import QObject, QThread, Signal

from client.client import sio, User, reg_callback, ensure_connected

username = None
user = User(None)
target_user = None

# =========================
# Socket.IO client wrapper
# =========================

class SocketIOClient(QObject):
    message_received = Signal(str)

    def run(self):
        def on_message(data):
            self.message_received.emit(data)

        reg_callback(user, on_message)
        sio.wait()


class Worker(QThread):
    message_received = Signal(str)
    user_joined = Signal(str)
    user_left = Signal(str)
    file_received = Signal(bytes, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True

    def run(self):
        def on_message(data):
           # Qui ricevi il messaggio dal server e lo ritrasmetti come segnale
            self.message_received.emit(data)

        def on_joined(username_):
            # Utente entrato, segnala alla GUI
            self.user_joined.emit(username_)

        def on_left(username_):
            # Utente uscito, segnala alla GUI
            self.user_left.emit(username_)

        def on_file_msg(event_tuple):
            event, plaintext, filename, peer = event_tuple
            if event == "file_received":
                self.file_received.emit(plaintext, filename, peer)

        reg_callback(user, on_message, joined_event=on_joined, left_event=on_left, gui_queue=on_file_msg)

        # Socket.IO client bloccante: gira finché la connessione è attiva
        sio.wait()

    def stop(self):
        self._running = False
        try:
            sio.disconnect()
        except Exception as e:
            print("Errore durante la disconnessione Socket.IO:", e)


# =========================
# Qt Application + Screens
# =========================

app = QApplication(sys.argv)


class LoginScreen(QWidget):
    def __init__(self, parent=None):
        super(LoginScreen, self).__init__(parent)
        self.setWindowTitle("Login")
        self.username_label = QLabel("Username:")
        self.username_edit = QLineEdit()
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: red;")

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_edit)
        layout.addWidget(self.login_button)
        layout.addWidget(self.error_label)
        self.setLayout(layout)

    def handle_login(self):
        ensure_connected()

        global username
        global user

        username = self.username_edit.text().strip()
        user.username = username

        self.error_label.setText("")

        if user.register_user():
           self.parent().switch_to_select_screen_first_time()

        else:
            self.error_label.setText("Username già in uso, scegline un altro.")


class SelectScreen(QWidget):
    def __init__(self, parent=None):
        super(SelectScreen, self).__init__(parent)
        self.setWindowTitle("Select")

        self.main_layout = QVBoxLayout()
        self.main_layout.addWidget(QLabel(f"Hi {username}!"))
        self.main_layout.addWidget(QLabel("<h2>Connect to:</h2>"))

        logout_button = QPushButton("Logout")
        logout_button.clicked.connect(self.handle_logout)
        self.main_layout.addWidget(logout_button)

        self.user_layout = QVBoxLayout()
        self.main_layout.addLayout(self.user_layout)

        self.user_buttons = {}

        self.setLayout(self.main_layout)

    def handle_logout(self):
        try:
            sio.emit("logout")  # non blocca la GUI
        except Exception as e:
            print("Errore logout:", e)

        app_ = QApplication.instance()
        if app_ is not None:
            app_.quit()

    def user_clicked(self, name):
        global target_user
        target_user = name
        print("target", target_user)
        if not user.is_connected(target_user):
            user.request_user_prekey_bundle(target_user)
            user.perform_x3dh(target_user)
            print("connected to", target_user)
        self.parent().switch_to_chat_screen()

    def add_user_button(self, name):
        if name == username:
            return
        if name in self.user_buttons:
            return
        button = QPushButton(name)
        button.clicked.connect(lambda _, n=name: self.user_clicked(n))
        self.user_layout.addWidget(button)
        self.user_buttons[name] = button

    def remove_user_button(self, name):
        btn = self.user_buttons.pop(name, None)  # <-- nessun errore se non esiste
        if btn is None:
            return
        try:
            btn.setParent(None)
            btn.deleteLater()
        except RuntimeError:
            print("Errore nella rimozione del bottone (già distrutto?)")


class ChatScreen(QWidget):
    def __init__(self, main_window, parent=None):
        super(ChatScreen, self).__init__(parent)
        self.setWindowTitle("Chat")
        self.main_window = main_window
        self.target_user = target_user

        self.input_field = QLineEdit()

        xlayout = QVBoxLayout()
        chat_layout = QHBoxLayout()

        back_button = QPushButton("Back")
        back_button.clicked.connect(self.back_message)
        toolbar_layout = QHBoxLayout()
        xlayout.addLayout(toolbar_layout)
        toolbar_layout.addWidget(back_button)
        toolbar_layout.addWidget(QLabel(f"{username} -> {target_user}"))

        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        xlayout.addWidget(self.chat_history)

        self.input_field = QLineEdit()
        send_button = QPushButton("Send")
        send_button.clicked.connect(self.send_message)

        file_button = QPushButton("File")           # <-- nuovo bottone
        file_button.clicked.connect(self.send_file)

        chat_layout.addWidget(self.input_field)
        chat_layout.addWidget(send_button)
        chat_layout.addWidget(file_button)
        
        xlayout.addLayout(chat_layout)

        self.setLayout(xlayout)

        self.update_messages(user.messages.get(target_user, []))

    def send_file(self):
        global target_user
        if target_user is None:
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleziona un file da inviare",
            "",
            "Tutti i file (*.*)"
        )
        if not file_path:
            return

        user.send_file(target_user, file_path)

        # opzionale: mostra qualcosa in chat
        messages = user.messages.setdefault(target_user, [])
        messages.append((username, f"[FILE] {file_path}"))
        self.update_messages(messages)

    def send_message(self):
        message = self.input_field.text()

        if message:
            self.input_field.clear()
            print("sending")
            user.send_message(target_user, message)
            self.update_messages(user.messages[target_user])


    def update_messages(self, messages):
        self.chat_history.clear()
        for sender, msg in messages:
            color = "green" if sender == username else "red"
            self.append_colored_text(sender, msg, color)

    def back_message(self):
        self.main_window.switch_to_select_screen_refresh()

    def append_colored_text(self, sender, msg, color):
        self.chat_history.append(
            f"<font color='{color}'> <strong>{sender}:</strong> {msg}</font><br>"
        )


class MainWindow(QMainWindow):
    def __init__(self, worker, parent=None):
        super(MainWindow, self).__init__(parent)
        self.worker = worker

        self.user_joined_signal = worker.user_joined
        self.user_left_signal = worker.user_left
        self.message_received_signal = worker.message_received

        self.login_screen = LoginScreen(self)
        self.select_screen = None
        self.chat_screen = None
        self.setCentralWidget(self.login_screen)

        # Connessioni segnali dal worker alla GUI
        self.user_joined_signal.connect(self.on_user_joined_gui)
        self.user_left_signal.connect(self.on_user_left_gui)
        self.message_received_signal.connect(self.on_message_received_gui)
        self.worker.file_received.connect(self.handle_file_received)

    def handle_file_received(self, plaintext: bytes, filename: str, peer: str):
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Salva file ricevuto",
            filename,
            "Tutti i file (*.*)"
        )

        messages_for_peer = user.messages.setdefault(peer, [])

        if not save_path:
            messages_for_peer.append((peer, f"[FILE REJECTED] {filename}"))
        else:

            with open(save_path, "wb") as f:
                f.write(plaintext)
            messages_for_peer.append(
                (peer, f"[FILE RICEVUTO] {filename} -> {save_path}")
            )

        if self.chat_screen is not None:
            # se si aspetta solo i messaggi di quel peer
            self.chat_screen.update_messages(messages_for_peer)
            # oppure, se si aspetta tutto il dict:
            # self.chat_screen.update_messages(user.messages)



    def on_user_joined_gui(self, username_):
        print("GUI SLOT: user joined", username_)
        if hasattr(self, "select_screen"):
            self.select_screen.add_user_button(username_)

    def on_user_left_gui(self, username_):
        print("GUI SLOT: user left", username_)

        if self.select_screen is not None:
            self.select_screen.remove_user_button(username_)

        global target_user
        current = self.centralWidget()
        if isinstance(current, ChatScreen) and target_user == username_:
            self.switch_to_select_screen_refresh()

    def on_message_received_gui(self, data):
        global target_user

        current = self.centralWidget()

        if isinstance(current, ChatScreen) and target_user is not None:
            messages = user.messages.get(target_user, [])
            self.update_chat(messages)
        else:
            print("Non sono in ChatScreen, non aggiorno la chat")

    def switch_to_select_screen_first_time(self):
        self.select_screen = SelectScreen(self)
        for u in getattr(user, "initial_users", []):
            self.select_screen.add_user_button(u)
        self.setCentralWidget(self.select_screen)


    def switch_to_select_screen_refresh(self):
        users = user.send_users()
        print(users)
        self.select_screen = SelectScreen(self)

        for u in users:
            if u != user.username:
                self.select_screen.add_user_button(u)

        self.setCentralWidget(self.select_screen)


    def switch_to_chat_screen(self):
        self.chat_screen = ChatScreen(self)
        self.setCentralWidget(self.chat_screen)


    def update_chat(self, messages):
         self.chat_screen.update_messages(messages)

    def closeEvent(self, event):
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(2000)
        super().closeEvent(event)


# =========================
# Avvio applicazione
# =========================

if __name__ == "__main__":
    worker_thread = Worker()
    mw = MainWindow(worker_thread)
    mw.show()

    worker_thread.start()

    sys.exit(app.exec())
