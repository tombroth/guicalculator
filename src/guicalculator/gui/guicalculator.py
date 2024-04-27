"""
guicalculator.py - This is the gui calculator main window. 
"""

"""
Copyright (c) 2024 Thomas Brotherton

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from tkinter import Tk, font

from .calcfrm import CalcFrm
from .calcstyle import CalcStyle


class GuiCalculator:
    """GuiCalculator - The root calculator window"""

    def __init__(self) -> None:
        self.root = Tk()
        self.root.title("Calculator")

        # style info for buttons
        self.style = CalcStyle()

        # set the font
        self.default_font = font.nametofont("TkDefaultFont")
        self.default_font.configure(size=12, weight=font.BOLD)
        self.root.option_add("*Font", self.default_font)

        # frame that contains the calculator
        self.calcfrm = CalcFrm(master=self.root)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # set size
        self.root.geometry("400x500")
        self.root.minsize(400, 500)

        # start tkinter
        self.root.mainloop()
