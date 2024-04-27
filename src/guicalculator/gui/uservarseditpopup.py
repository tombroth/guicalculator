"""
uservarseditpopup.py - This is the gui calculator user variables editor popup 
window.
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

from tkinter import Tk, Toplevel

from ..calculator import CalculatorData
from .uservarseditfrm import UserVarsEditFrm


class UserVarsEditPopup:
    """UserVarsEditPopup - Popup window to edit the user variables."""

    def __init__(
        self,
        x: int,
        y: int,
        calculator_data: CalculatorData,
        vptf_topwin: Tk | Toplevel,
    ) -> None:
        self.win = Toplevel()
        self.calculator_data = calculator_data
        self.topwin = vptf_topwin

        self.win.focus_set()
        self.win.wm_title("Edit User Variables")

        self.win.focus_set()
        self.treefrm = UserVarsEditFrm(
            master=self.win,
            calculator_data=self.calculator_data,
            vptf_topwin=vptf_topwin,
        )
        self.win.rowconfigure(0, weight=1)
        self.win.columnconfigure(0, weight=1)
        self.win.geometry("+%d+%d" % (x, y))
