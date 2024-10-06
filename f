import sys
import socket
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QLineEdit, QPushButton,
    QVBoxLayout, QWidget, QTextBrowser, QMessageBox, QHBoxLayout, QAction, QToolBar
)
from PyQt5.QtGui import QSyntaxHighlighter, QTextCharFormat, QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl, QByteArray
import logging
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineProfile, QWebEngineUrlScheme, QWebEngineUrlRequestJob, \
    QWebEngineUrlSchemeHandler

# Настройки сервера
HOST = '127.0.0.1'  # Локальный хост для тестирования
PORT = 8080

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')


class HtmlHighlighter(QSyntaxHighlighter):
    def highlightBlock(self, text):
        # Пример простой подсветки HTML-тегов
        tags = ['<html>', '</html>', '<head>', '</head>', '<body>', '</body>', '<title>', '</title>',
                '<h1>', '</h1>', '<p>', '</p>', '<div>', '</div>', '<span>', '</span>',
                '<style>', '</style>', '<script>', '</script>', '<link>', '>']
        tag_format = QTextCharFormat()
        tag_format.setForeground(Qt.blue)
        for tag in tags:
            start_index = text.find(tag)
            while start_index >= 0:
                length = len(tag)
                self.setFormat(start_index, length, tag_format)
                start_index = text.find(tag, start_index + length)


class SMPSchemeHandler(QWebEngineUrlSchemeHandler):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.cache = {}

    def requestStarted(self, job: QWebEngineUrlRequestJob):
        url = job.requestUrl().toString()
        logging.info(f"Загрузка ресурса: {url}")

        if url in self.cache:
            logging.info(f"Ресурс найден в кеша: {url}")
            job.reply(b'text/plain', self.cache[url])
            return

        thread = SMPResourceLoadThread(url)
        thread.finished.connect(lambda data, mime: self.handle_response(job, data, mime))
        thread.start()

    def handle_response(self, job, data, mime):
        self.cache[job.requestUrl().toString()] = data
        job.reply(mime.encode(), data)


class SMPResourceLoadThread(QThread):
    finished = pyqtSignal(bytes, str)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        # Преобразуем smp://example.com/style.css в example.com/style.css
        parts = QUrl(self.url).path().split('/', 1)
        if len(parts) != 2:
            self.finished.emit(b'', 'text/plain')
            return
        resource, path = parts
        smp_url = QUrl(f"smp://{resource}/{path}").toString()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.connect((HOST, PORT))
                request = f"SMP 1.0\nACTION: GET\nRESOURCE: {resource}/{path}\n"
                logging.info(f"Отправляем запрос на ресурс:\n{request}")
                sock.sendall(request.encode())

                response = b""
                while True:
                    part = sock.recv(4096)
                    if not part:
                        break
                    response += part

                response_str = response.decode(errors='ignore')
                logging.info(f"Получен ответ на ресурс:\n{response_str[:100]}...")

                headers, _, body = response_str.partition('\n\n')
                status_line = headers.splitlines()[1].strip()

                if status_line.startswith("STATUS: OK"):
                    self.finished.emit(body.encode(), 'text/css')  # Здесь нужно определить MIME тип
                else:
                    self.finished.emit(b'', 'text/plain')
            except Exception as e:
                logging.error(f"Ошибка при загрузке ресурса: {e}")
                self.finished.emit(b'', 'text/plain')


class LoadUrlThread(QThread):
    finished = pyqtSignal(str, str)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        parts = self.url.split('://')
        if len(parts) != 2 or parts[0].lower() != 'smp':
            self.finished.emit(self.url, "Неверный URL: должен начинаться с 'smp://'")
            return

        resource = parts[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.connect((HOST, PORT))
                request = f"SMP 1.0\nACTION: GET\nRESOURCE: {resource}\n"
                logging.info(f"Отправляем запрос:\n{request}")
                sock.sendall(request.encode())

                response = b""
                while True:
                    part = sock.recv(4096)
                    if not part:
                        break
                    logging.info(f"Получен фрагмент: {part}")
                    response += part

                response_str = response.decode(errors='ignore')
                logging.info(f"Получен ответ:\n{response_str[:100]}...")

                headers, _, body = response_str.partition('\n\n')
                lines = headers.split('\n')
                if len(lines) < 2:
                    self.finished.emit(self.url, "Неверный ответ от сервера.")
                    return

                status_line = lines[1].strip()
                if status_line.startswith("STATUS: OK"):
                    self.finished.emit(self.url, body)
                else:
                    message = lines[2].strip() if len(lines) > 2 else "Неизвестная ошибка"
                    self.finished.emit(self.url, f"Ошибка: {message}")

            except Exception as e:
                self.finished.emit(self.url, f"Ошибка подключения: {str(e)}")


class Tab(QWidget):
    def __init__(self, handler, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)

        # Создаем QWebEngineView для отображения HTML
        self.webView = QWebEngineView()
        self.webView.setContextMenuPolicy(Qt.NoContextMenu)
        self.layout.addWidget(self.webView)

        # Создаем QTextBrowser для отображения исходного кода HTML
        self.htmlViewer = QTextBrowser()
        self.htmlViewer.setReadOnly(True)
        self.htmlViewer.setStyleSheet("background-color: #f0f0f0; border: 1px solid #ccc;")
        self.htmlViewer.setFixedHeight(200)
        self.layout.addWidget(self.htmlViewer)

        # Инициализируем подсветку синтаксиса для QTextBrowser
        self.highlighter = HtmlHighlighter(self.htmlViewer.document())

        # Устанавливаем кастомный обработчик URL-схемы
        profile = QWebEngineProfile.defaultProfile()
        profile.installUrlSchemeHandler(b'smp', handler)

    def displayContent(self, content):
        # Отображаем HTML-контент в QWebEngineView
        if content.strip().lower().startswith("<!doctype html") or content.strip().lower().startswith("<html"):
            base_url = QUrl("smp://localhost/")  # Базовый URL для разрешения относительных путей
            self.webView.setHtml(content, base_url)
        else:
            # Оборачиваем контент в простой HTML-документ
            base_url = QUrl("smp://localhost/")
            self.webView.setHtml(
                f"<!DOCTYPE html><html><head><meta charset='UTF-8'></head><body>{content}</body></html>", base_url)

        # Отображаем исходный код в QTextBrowser
        self.htmlViewer.setPlainText(content)
        self.highlighter.rehighlight()


class Browser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SMP Browser")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("background-color: #ffffff; font-family: 'Arial', sans-serif;")

        # Настройка кастомного обработчика схемы
        scheme_handler = SMPSchemeHandler(self)

        self.tabWidget = QTabWidget()
        self.setCentralWidget(self.tabWidget)

        self.history = []
        self.forward_history = []
        self.createMainTab()
        self.last_url = None  # Для отслеживания последнего загруженного URL

        # Настройка меню
        self.createMenuBar()

    def createMenuBar(self):
        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&Файл')

        newTabAction = QAction('Новая вкладка', self)
        newTabAction.setShortcut('Ctrl+T')
        newTabAction.triggered.connect(self.addTab)
        fileMenu.addAction(newTabAction)

        exitAction = QAction('Выход', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.triggered.connect(self.close)
        fileMenu.addAction(exitAction)

        helpMenu = menubar.addMenu('&Помощь')
        aboutAction = QAction('О программе', self)
        aboutAction.triggered.connect(self.showAbout)
        helpMenu.addAction(aboutAction)

    def showAbout(self):
        QMessageBox.information(self, "О программе", "SMP Browser v1.0\nАвтор: Ваше Имя")

    def createMainTab(self):
        handler = SMPSchemeHandler(self)
        tab = Tab(handler)

        # Создаем виджеты для URL и кнопок
        urlLayout = QHBoxLayout()
        self.urlEdit = QLineEdit()
        self.urlEdit.setPlaceholderText("Введите URL (smp://...)")
        self.urlEdit.setStyleSheet("padding: 10px; border: 1px solid #ccc; border-radius: 4px;")
        urlLayout.addWidget(self.urlEdit)

        loadButton = QPushButton(QIcon.fromTheme("document-open"), "Загрузить")
        loadButton.clicked.connect(self.loadUrlInCurrentTab)
        urlLayout.addWidget(loadButton)

        testHtmlButton = QPushButton(QIcon.fromTheme("view-refresh"), "Загрузить тестовый HTML")
        testHtmlButton.clicked.connect(self.loadTestHtml)
        urlLayout.addWidget(testHtmlButton)

        # Добавление навигационных кнопок
        backButton = QPushButton(QIcon.fromTheme("go-previous"), "Назад")
        backButton.clicked.connect(self.goBack)
        urlLayout.addWidget(backButton)

        forwardButton = QPushButton(QIcon.fromTheme("go-next"), "Вперед")
        forwardButton.clicked.connect(self.goForward)
        urlLayout.addWidget(forwardButton)

        refreshButton = QPushButton(QIcon.fromTheme("view-refresh"), "Обновить")
        refreshButton.clicked.connect(self.refreshPage)
        urlLayout.addWidget(refreshButton)

        # Добавление в тулбар
        toolbar = QToolBar()
        toolbar.addLayout(urlLayout)
        self.addToolBar(toolbar)

        # Создаем основной вертикальный макет
        mainLayout = QVBoxLayout()
        mainLayout.addWidget(tab)

        container = QWidget()
        container.setLayout(mainLayout)
        self.tabWidget.addTab(container, "Новая вкладка")

    def loadTestHtml(self):
        test_html = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Тестовый HTML</title>
    <link rel="stylesheet" href="smp://example.com/styles.css">
    <style>
        body { background-color: #f4f4f4; color: #333; }
        h1 { color: green; }
    </style>
</head>
<body>
    <h1>Это тестовый HTML документ!</h1>
    <p>Проверяем отображение HTML-кода.</p>
    <img src="smp://example.com/img.png" alt="Test Image">
</body>
</html>"""
        currentTabIndex = self.tabWidget.currentIndex()
        currentTabWidget = self.tabWidget.widget(currentTabIndex)
        tab = currentTabWidget.findChild(Tab)
        tab.displayContent(test_html)

    def loadUrlInCurrentTab(self):
        currentTabIndex = self.tabWidget.currentIndex()
        if currentTabIndex == -1:
            return

        currentTabWidget = self.tabWidget.widget(currentTabIndex)
        tab = currentTabWidget.findChild(Tab)
        if not tab:
            self.showError("Не удалось найти текущую вкладку.")
            return

        url = self.urlEdit.text().strip()
        if not url:
            self.showError("Пожалуйста, введите URL.")
            return

        # Проверка на двойное нажатие
        if url == self.last_url:
            logging.info("URL не изменился, загрузка отменена.")
            return  # Не загружать, если URL не изменился
        self.last_url = url  # Обновить последний загруженный URL

        logging.info(f"Загрузка URL: {url}")
        self.loadSmpUrl(url, tab)

    def loadSmpUrl(self, url, tab):
        self.thread = LoadUrlThread(url)
        self.thread.finished.connect(lambda url, response: self.handleResponse(url, response, tab))
        self.thread.start()

    def handleResponse(self, url, response, tab):
        if response.startswith("Ошибка:") or "Неверный URL" in response:
            self.showError(response)
        else:
            # Передаём весь HTML-документ
            full_html = response
            self.last_url = url
            tab.displayContent(full_html)
            self.history.append(url)  # Сохраняем URL в истории
            self.forward_history.clear()  # Очистить историю вперед при новом запросе

    def showError(self, message):
        QMessageBox.critical(self, "Ошибка", message)

    def addTab(self):
        handler = SMPSchemeHandler(self)
        tab = Tab(handler)

        # Обновляем интерфейс для новой вкладки
        self.tabWidget.addTab(tab, "Новая вкладка")
        self.tabWidget.setCurrentWidget(tab)

    def goBack(self):
        if not self.history:
            QMessageBox.information(self, "Info", "История пуста.")
            return
        last_url = self.history.pop()  # Убираем последний URL из истории
        self.forward_history.append(self.last_url)  # Добавляем текущий URL в историю вперед
        self.urlEdit.setText(last_url)
        self.loadUrlInCurrentTab()

    def goForward(self):
        if not self.forward_history:
            QMessageBox.information(self, "Info", "История вперед пуста.")
            return
        next_url = self.forward_history.pop()
        self.history.append(self.last_url)
        self.urlEdit.setText(next_url)
        self.loadUrlInCurrentTab()

    def refreshPage(self):
        currentTabIndex = self.tabWidget.currentIndex()
        if currentTabIndex != -1:
            currentTabWidget = self.tabWidget.widget(currentTabIndex)
            tab = currentTabWidget.findChild(Tab)
            if tab:
                tab.webView.reload()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Регистрация схемы 'smp'
    smp_scheme = QWebEngineUrlScheme(b'smp')
    smp_scheme.setSyntax(QWebEngineUrlScheme.Syntax.Path)
    smp_scheme.setDefaultPort(PORT)
    smp_scheme.setFlags(QWebEngineUrlScheme.Flag.LocalScheme | QWebEngineUrlScheme.Flag.ContentSecurityPolicyIgnored)
    QWebEngineProfile.defaultProfile().registerUrlScheme(smp_scheme)

    window = Browser()
    window.show()
    sys.exit(app.exec_())
