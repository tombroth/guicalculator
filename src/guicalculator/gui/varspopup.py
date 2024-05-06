"""
varspopup.py - This is the gui calculator user variables selector popup 
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

from tkinter import Toplevel

from ..calculator import CalculatorData
from ..globals import TkEvents
from .varspopuptreefrm import VarsPopupTreeFrm
from .varspopuptreefrmbuttons import VarsPopupTreeFrmButtons


class VarsPopup:
    """VarsPopup - The popup window to display variables."""

    def __init__(self, x: int, y: int, calculator_data: CalculatorData) -> None:
        self.win = Toplevel()
        self.calculator_data = calculator_data

        self.win.focus_set()
        self.win.wm_title("Variables")

        self.treefrm = VarsPopupTreeFrm(
            master=self.win, calculator_data=calculator_data
        )
        self.win.rowconfigure(0, weight=1)
        self.win.columnconfigure(0, weight=1)

        vars_tree = self.treefrm.vars_tree
        if vars_tree.get_children():
            vars_tree.focus(vars_tree.get_children()[0])
            vars_tree.selection_set(vars_tree.get_children()[0])

        self.win.geometry("+%d+%d" % (x, y))

        # add buttons
        self.buttonfrm = VarsPopupTreeFrmButtons(
            master=self.win,
            calculator_data=self.calculator_data,
            vars_tree=self.treefrm.vars_tree,
        )
        self.win.rowconfigure(1, weight=0)

        # double click event to select a variable
        self.treefrm.vars_tree.bind(
            TkEvents.DOUBLECLICK, lambda _: self.buttonfrm.select_button.invoke()
        )
