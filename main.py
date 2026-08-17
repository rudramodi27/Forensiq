import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

from forensiq.ui.main_window import MainWindow


def main():
    # ── HiDPI scaling — must be set BEFORE QApplication is created ────────────
    # Enables crisp rendering on 4K / Retina / HiDPI displays.
    os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("ForensIQ")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("ForensIQ Labs")

    # Base font — Segoe UI on Windows, SF Pro on macOS, system default elsewhere
    base_font = QFont("Segoe UI", 10)
    base_font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(base_font)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
