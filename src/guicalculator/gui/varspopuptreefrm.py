"""
varspopuptreefrm.py - This is the gui calculator user variables selector 
frame.
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

from ..calculator import (
    CalculatorData,
    get_user_variables,
    gui_object_wrapper,
    numtostr,
)
from ..globals import DEFAULT_VARIABLES, VariablesType


class VarsPopupTreeFrm:
    """VarsPopupTreeFrm - The frame with the variables displayed."""

    def __init__(self, master, calculator_data: CalculatorData) -> None:
        self.frm = ttk.Frame(master)
        self.calculator_data = calculator_data

        self.frm.focus_set()

        # scrollbar and treeview
        self.scrollbar = ttk.Scrollbar(self.frm, orient="vertical")
        self.vars_tree = ttk.Treeview(
            self.frm,
            yscrollcommand=self.scrollbar.set,
            columns=("value"),
            height=7,
            selectmode="browse",
        )
        self.scrollbar.configure(command=self.vars_tree.yview)
        self.vars_tree.focus_set()

        self.vars_tree.grid(row=0, column=0, sticky="news")
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.frm.columnconfigure(0, weight=1)
        self.frm.columnconfigure(1, weight=0)
        self.frm.rowconfigure(0, weight=1)

        # our columns in the tree view
        self.vars_tree.heading("#0", text="Variable")
        self.vars_tree.column("#0", width=150, anchor="w")

        self.vars_tree.heading("value", text="Value")
        self.vars_tree.column("value", width=325, anchor="w")

        # Add default variables
        self.add_variable_section("default", DEFAULT_VARIABLES)

        # Add user variables
        self.add_variable_section(
            "user variables", get_user_variables(self.calculator_data)
        )

        self.frm.grid(row=0, column=0, sticky="news")

    @gui_object_wrapper
    def add_variable_section(
        self, section_name: str, section_vars: VariablesType
    ) -> None:
        """
        add_variable_section - Add a variable dictionary to the tree frame

        Parameters
        ----------
        section_name : str
            Section Name
        section_vars : VariablesType : dict[str, Decimal]
            Variables
        """

        section_id = self.vars_tree.insert(
            "",
            "end",
            text=section_name,
            values=([""]),
        )
        for v_key, v_value in section_vars.items():
            self.vars_tree.insert(
                section_id,
                "end",
                text=v_key,
                values=([numtostr(v_value, commas=True)]),
            )
        self.vars_tree.item(section_id, open=True)
