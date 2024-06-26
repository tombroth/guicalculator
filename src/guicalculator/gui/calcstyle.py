"""
calcstyle.py - This is the gui calculator ttk.Style object. 
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

from tkinter import ttk

from ..globals import ButtonStyles


class CalcStyle:
    """CalcStyle - The ttk.Style object for the calculator"""

    def __init__(self) -> None:
        self.style = ttk.Style()
        self.style.theme_use("alt")

        self.style.map(
            ButtonStyles.NUMBER,
            foreground=[("active", "white"), ("!active", "white")],
            background=[("active", "gray45"), ("!active", "gray55")],
        )

        self.style.configure(ButtonStyles.ORANGE, background="darkorange2")
        self.style.configure(ButtonStyles.RED, background="orangered2")
        self.style.configure(ButtonStyles.MEMORY, background="lightcyan3")
        self.style.configure(ButtonStyles.MATHOP, background="cornsilk3")
