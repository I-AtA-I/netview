import sys

from PySide6.QtWidgets import QApplication

from netview.gui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("NetView")
    app.setOrganizationName("NetView")

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
