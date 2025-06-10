import os
import sys
from PyQt5.QtWidgets import QApplication, QStackedWidget
from PyQt5.QtGui import QFontDatabase, QFont

from intro_window import IntroWindow
from function_window import FunctionWindow
from select_window import SelectionWindow

class MainWindow(QStackedWidget):
    def __init__(self):
        super().__init__()

        self.intro = IntroWindow(self.route_from_intro)
        self.selection = SelectionWindow(self.show_function_screen)
        self.function = FunctionWindow(self.back_to_selection)

        self.addWidget(self.intro)
        self.addWidget(self.selection)
        self.addWidget(self.function)

        self.setWindowTitle("Erase Me")
        self.resize(1000, 700)

        self.setCurrentIndex(0)
        self.show()

    def route_from_intro(self):
        if os.path.exists("selected_fields.json"):
            self.show_function_screen()
        else:
            self.setCurrentIndex(1)

    def show_function_screen(self):
        self.function.reload_selected_fields()
        self.setCurrentIndex(2)

    def back_to_selection(self):
        if os.path.exists("selected_fields.json"):
            os.remove("selected_fields.json")
        self.setCurrentIndex(1)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    font_id = QFontDatabase.addApplicationFont("./public/Pretendard-Regular.otf")
    if font_id != -1:
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families:
            app.setFont(QFont(families[0], 12))
    
    def cleanup_masking_record():
        if os.path.exists("masking_record.json"):
            os.remove("masking_record.json")
            print("🧹 masking_record.json 삭제됨")

    app.aboutToQuit.connect(cleanup_masking_record)

    win = MainWindow()
    sys.exit(app.exec_())
