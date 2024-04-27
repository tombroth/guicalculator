"""
uservarseditfrm.py - This is the gui calculator user variables editor frame.
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

from tkinter import END, INSERT, Event, StringVar, Tk, Toplevel, ttk
from typing import Any

from ..calculator import (
    CalculatorData,
    evaluate_calculation,
    numtostr,
    strtodecimal,
    validate_user_var,
)
from ..globals import TkEvents, VariablesType


class UserVarsEditFrm:
    """UserVarsEditFrm - The frame with the user variables edit widgets"""

    def __init__(
        self, master, calculator_data: CalculatorData, vptf_topwin: Tk | Toplevel
    ) -> None:
        self.frm = ttk.Frame(master)
        self.calculator_data = calculator_data
        self.vptf_topwin = vptf_topwin

        # column headers
        self.var_lbl = ttk.Label(self.frm, text="User Variable", width=16)
        self.val_lbl = ttk.Label(self.frm, text="Value", width=32)

        lastrow: int = 0
        self.var_lbl.grid(row=lastrow, column=0, sticky="we")
        self.val_lbl.grid(row=lastrow, column=1, sticky="we")

        self.frm.rowconfigure(lastrow, weight=0)
        self.frm.columnconfigure(0, weight=1)
        self.frm.columnconfigure(1, weight=1)

        # validate functions for name/value
        self.validate_var_name = (self.frm.register(self.validate_varname), "%P")
        self.validate_value = (self.frm.register(self.validate_decimal), "%P")

        """
        variable name/value entry widgets

        This dictionary stores all the Text entry boxes for editing user 
        variables.
        
        The tuple[int, int] index is the row and column of the entry widget

        The frame row 0 is the header, so the first variable is row 1.

        Column 0 is variable name.
        Column 1 is variable value.

        So the first variable name is the entry widget at uservars[1,0] 
        not at uservars[0,0].
        """
        self.uservars: dict[tuple[int, int], ttk.Entry] = {}

        for k, v in self.calculator_data.user_variables.items():
            lastrow += 1
            self.addrow(lastrow, k, numtostr(v, commas=True))

        # if we had no rows, add a blank one
        if not self.uservars:
            lastrow += 1
            self.addrow(lastrow)

        self.uservars[(1, 0)].focus_set()

        # put these at row 1000 to allow for inserting more rows
        # add row button
        self.addbtn = ttk.Button(
            self.frm,
            text="Add Row",
            command=self.user_vars_edit_addrow,
        )
        self.addbtn.grid(row=1000, column=0)
        self.frm.rowconfigure(1000, weight=0)

        # add delete row nutton
        self.delbtn = ttk.Button(
            self.frm,
            text="Delete Row",
            command=self.user_vars_edit_delrow,
            takefocus=False,  # hack so I can see what edit row has focus
        )
        self.delbtn.grid(row=1000, column=1)

        # add current_calculation button
        self.curcalcbtn = ttk.Button(
            self.frm,
            text="Add current result as new variable",
            command=self.add_current,
        )
        self.curcalcbtn.grid(row=1001, column=0, columnspan=2)
        self.frm.rowconfigure(1001, weight=0)

        vptf_topwin = self.frm.winfo_toplevel()

        # ok button
        self.okbtn = ttk.Button(
            self.frm,
            text="Ok",
            command=self.user_vars_edit_ok,
        )
        self.okbtn.grid(row=1002, column=0)
        self.frm.rowconfigure(1002, weight=0)

        vptf_topwin.bind(TkEvents.RETURN, lambda _: self.okbtn.invoke())

        # cancel button
        self.cancelbtn = ttk.Button(
            self.frm, text="Cancel", command=vptf_topwin.destroy
        )
        self.cancelbtn.grid(row=1002, column=1)

        vptf_topwin.bind(TkEvents.ESCAPE, lambda _: self.cancelbtn.invoke())

        # error message display
        self.errmsg = StringVar(self.frm)
        self.errmsg_lbl = ttk.Label(self.frm, anchor="w", textvariable=self.errmsg)
        self.errmsg_lbl.grid(row=1003, column=0, columnspan=2, sticky="news")
        self.frm.rowconfigure(1003, weight=0)

        self.frm.grid(row=0, column=0, sticky="news")

    def user_vars_edit_delrow(self) -> None:
        """Delete the current row"""

        # find the current row
        cur_widget = self.frm.winfo_toplevel().focus_get()
        if cur_widget in list(self.uservars.values()):
            widget_num = list(self.uservars.values()).index(cur_widget)  # type: ignore
            row = list(self.uservars.keys())[widget_num][0]

            # found it, now destroy entry widgets and remove from dictionary
            self.uservars[(row, 0)].destroy()
            self.uservars[(row, 1)].destroy()
            self.uservars.pop((row, 0), None)
            self.uservars.pop((row, 1), None)

            # if we still have entry widgets, set focus to one of them
            if self.uservars:
                remaining_vars = list(self.uservars.keys())
                if widget_num >= len(remaining_vars):
                    widget_num = -1
                self.uservars[remaining_vars[widget_num]].focus_set()

    def add_current(self) -> None:
        """Add the current calculation result as a variable"""

        currcalc = self.calculator_data.get_current_eval_calc()
        if currcalc:
            # get the result
            try:
                # calling the parser directly so we don't mess with the current display
                result = evaluate_calculation(
                    currcalc, self.calculator_data.user_variables
                )
            except:
                s = self.calculator_data.get_current_display_calc()
                trimlen = 35
                if len(s) > trimlen:
                    s = s[: (trimlen - 4)] + " ..."
                self.set_errmsg(f"Invalid calculation: {s}")
                return

            # add result to a new row
            row = self.user_vars_edit_addrow()

            self.uservars[(row, 0)].delete(0, END)
            self.uservars[(row, 0)].insert(0, "x")

            self.uservars[(row, 1)].delete(0, END)
            self.uservars[(row, 1)].insert(0, numtostr(result, commas=True))

    def addrow(self, rownum: int, var: str = "", val: str = "") -> None:
        """
        addrow - Add a row for a new variable

        Parameters
        ----------
        rownum : int
            Row number
        var : str, optional
            Variable name, by default ""
        val : str, optional
            Variable value, by default ""
        """

        self.addtextbox(rownum, 0, var)
        self.addtextbox(rownum, 1, val)

    def addtextbox(self, rownum: int, colnum: int, text: str = "") -> None:
        """
        addtextbox - Add a text entry box for variable name or variable value

        Parameters
        ----------
        rownum : int
            Text box row number
        colnum : int
            Text box column number, 0 for variable name, 1 for variable value
        text : str, optional
            Initial text to put in box, by default ""
        """

        entopts: dict[str, Any]  # entry widget validation options
        if colnum == 0:
            entopts = {
                "validate": "key",
                "validatecommand": self.validate_var_name,
            }
        elif colnum == 1:
            entopts = {
                "validate": "key",
                "validatecommand": self.validate_value,
            }
        else:
            entopts = {}

        tbox = ttk.Entry(self.frm, width=(16 * (colnum + 1)), **entopts)
        tbox.insert(INSERT, text)
        tbox.grid(row=rownum, column=colnum, sticky="news")
        self.uservars[(rownum, colnum)] = tbox
        self.frm.rowconfigure(rownum, weight=1)

        if colnum == 1:
            tbox.bind(TkEvents.KEYRELEASE, self.format_number)

    def format_number(self, event: Event) -> None:
        """
        format_number - Format the number input

        Parameters
        ----------
        event : tk.Event
            The event triggering this call
        """

        v = event.widget.get()
        if v:
            # if we have an entry, get it and format it
            v_decimal = strtodecimal(v)
            v_str = numtostr(v_decimal, commas=True, removeZeroes=False)
            if v[-1] == ".":
                v_str += "."
            event.widget.delete(0, END)
            event.widget.insert(0, v_str)

    def validate_varname(self, newnam: str) -> bool:
        """
        validate_varname - Validate that the variable being entered
        is a valid variable name

        Only validates that the new name is a valid identifier. Does
        not check for keywords or duplicate names because input may
        not be completed.

        Parameters
        ----------
        newnam : str
            New variable name

        Returns
        -------
        bool
            True if the name is a valid identifier, False if not.
        """

        if newnam and not newnam.isidentifier():
            self.frm.bell()
            return False

        return True

    def validate_decimal(self, newval: str) -> bool:
        """
        validate_decimal - Validate that the number being entered is a
        valid Decimal.

        Parameters
        ----------
        newval : str
            The number being entered

        Returns
        -------
        bool
            True if the number is a valid Decimal, False if not.
        """

        if newval:
            try:
                _ = strtodecimal(newval)
            except:
                self.frm.bell()
                return False

        return True

    def user_vars_edit_addrow(self) -> int:
        """
        user_vars_edit_addrow - Add a row for a new user variable. Returns row
        number added
        """

        if self.uservars.keys():
            nextrow = max(r for (r, _) in self.uservars.keys()) + 1
        else:
            nextrow = 1

        self.addrow(nextrow)
        self.uservars[(nextrow, 0)].focus_set()

        return nextrow

    def user_vars_edit_ok(self) -> None:
        """user_vars_edit_ok - Update the user variables from entered data"""

        newuservars: VariablesType = VariablesType({})

        if self.uservars:
            k = self.uservars.keys()
            rows = set(
                list(zip(*k))[0]
            )  # unique set of rows that haven't been deleted yet
        else:
            rows = set()

        for i in rows:
            # user variable name
            nam = self.uservars[(i, 0)].get().strip()

            # new user variable value
            val = self.uservars[(i, 1)].get().strip()

            # common parts of these error messages
            # extracted for consistency in messaging
            errmsg = f"ERROR:"
            varnam = f"variable name {nam!r}"

            # get the decimal value of variable
            if val:
                try:
                    val_decimal = +strtodecimal(val)
                except:
                    self.set_errmsg(f"{errmsg} invalid numeric value {val!r}")
                    self.uservars[(i, 1)].focus_set()
                    return
            else:
                self.set_errmsg(f"{errmsg} value not set")
                self.uservars[(i, 1)].focus_set()
                return

            # validate nam and val_decimal
            try:
                validate_user_var(nam, val_decimal)
            except Exception as e:
                self.set_errmsg(f"{errmsg} {str(e)}")
                self.uservars[(i, 0)].focus_set()
                return

            # above doesn't check for duplicate in enterred variable list
            # if we  have a duplicate variable name, print an error
            if nam in newuservars.keys():
                self.set_errmsg(f"{errmsg} duplicate {varnam}")
                self.uservars[(i, 0)].focus_set()
                return

            newuservars[nam] = val_decimal

        # save the new variables
        self.calculator_data.user_variables = newuservars

        # close this window
        self.frm.winfo_toplevel().destroy()

        # rebuild the varspopup
        self.vptf_topwin.destroy()
        self.calculator_data.vars_popup()

    def set_errmsg(self, error_msg: str) -> None:
        """
        set_errmsg - Set the error message and ring a bell

        Parameters
        ----------
        error_msg : str
            Error message to display
        """
        self.frm.bell()
        self.errmsg.set(error_msg)
