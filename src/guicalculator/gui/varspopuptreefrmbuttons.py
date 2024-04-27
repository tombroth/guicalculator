"""
varspopuptreefrmbuttons.py - This is the gui calculator user variables selector 
button frame.
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

from ..calculator import CalculatorData
from ..globals import TkEvents
from .uservarseditpopup import UserVarsEditPopup


class VarsPopupTreeFrmButtons:
    """
    VarsPopupTreeFrmButtons - The frame with the buttons in the variables
    popup window.
    """

    def __init__(
        self, master, calculator_data: CalculatorData, vars_tree: ttk.Treeview
    ) -> None:
        self.frm = ttk.Frame(master)
        self.calculator_data = calculator_data
        self.vars_tree = vars_tree

        self.edit_button = ttk.Button(
            self.frm,
            text="Edit User Variables",
            command=self.user_vars_edit,
        )
        self.edit_button.grid(row=0, column=0, columnspan=2)
        self.frm.columnconfigure(0, weight=1)
        self.frm.rowconfigure(0, weight=0)

        self.select_button = ttk.Button(
            self.frm,
            text="Select",
            command=self.user_vars_select,
        )
        self.select_button.grid(row=1, column=0)
        self.frm.rowconfigure(1, weight=0)

        self.cancel_button = ttk.Button(
            self.frm,
            text="Cancel",
            command=self.frm.winfo_toplevel().destroy,
        )
        self.cancel_button.grid(row=1, column=1)
        self.frm.columnconfigure(1, weight=1)

        top_win = self.frm.winfo_toplevel()
        top_win.bind(TkEvents.RETURN, lambda _: self.select_button.invoke())
        top_win.bind(TkEvents.ESCAPE, lambda _: self.frm.winfo_toplevel().destroy())
        self.frm.grid(row=1, column=0, sticky="news")

    def user_vars_select(self) -> None:
        """user_vars_select - Return selected variable to the calculator."""

        vars_tree = self.vars_tree

        # if we have one of the variables selected
        # not on "default" or "user variables"
        if (
            vars_tree.selection()
            and vars_tree.selection()[0] not in vars_tree.get_children()
        ):
            self.calculator_data.button_press(
                vars_tree.item(vars_tree.selection()[0])["text"]
            )

        self.frm.winfo_toplevel().destroy()

    def user_vars_edit(self) -> None:
        """user_vars_edit - Popup window to edit the user variables."""

        x = self.frm.winfo_toplevel().winfo_x() + 10
        y = self.frm.winfo_toplevel().winfo_y() + 10
        self.editvars_win = UserVarsEditPopup(
            x,
            y,
            calculator_data=self.calculator_data,
            vptf_topwin=self.vars_tree.winfo_toplevel(),
        )
