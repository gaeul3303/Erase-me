from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt

class IntroWindow(QWidget):
    def __init__(self, start_callback):
        super().__init__()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(30)

        logo = QPixmap("./public/logo.png")
        logo_label = QLabel()
        logo_label.setPixmap(logo.scaled(400, 400, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_label.setAlignment(Qt.AlignCenter)

        start_btn = QPushButton("시작하기")
        start_btn.setFixedSize(200, 50)
        start_btn.setStyleSheet("""
            QPushButton {
                background-color: #3e5879;
                color: white;
                font-weight: bold;
                font-size: 18px;
                font-family: Pretendard;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #576981;
            }
        """)
        start_btn.clicked.connect(start_callback)

        layout.addWidget(logo_label)
        layout.addSpacing(50)
        layout.addWidget(start_btn, alignment=Qt.AlignCenter)

        self.setLayout(layout)
