"""
main.py
NetTrace — AI-Powered Network Attack Path Reconstruction


"""

import tkinter as tk
from gui import NetTraceGUI


def main():
    root = tk.Tk()
    app = NetTraceGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()