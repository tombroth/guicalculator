"""
guicalculator.py - This is the gui calculator main window. 

Can be exeecuted as a module:
    python3 -m guicalculator

Or it can be run directly:
    guicalculator

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

import tkinter as tk
from tkinter import font, scrolledtext, ttk
from typing import Any, Dict, Tuple

from .buttoncfg import ButtonInfo, ButtonLocation, buttons
from .calculatordata import CalculatorData
from .globals import DEFAULT_VARIABLES, VariablesType
from .supportfuncs import numtostr, strtodecimal, validate_user_var


class GuiCalculator:
    """GuiCalculator - The root calculator window"""

    def __init__(self) -> None:
        self.root = tk.Tk()
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


class CalcStyle:
    """CalcStyle - The ttk.Style object for the calculator"""

    def __init__(self) -> None:
        self.style = ttk.Style()
        self.style.theme_use("alt")

        self.style.map(
            "number.TButton",
            foreground=[("active", "white"), ("!active", "white")],
            background=[("active", "gray45"), ("!active", "gray55")],
        )

        self.style.configure("orange.TButton", background="darkorange2")
        self.style.configure("red.TButton", background="orangered2")
        self.style.configure("memory.TButton", background="lightcyan3")
        self.style.configure("mathop.TButton", background="cornsilk3")


class CalcFrm:
    """
    CalcFrm - The main frame of the calculator root window. Everything is
    in this frame.
    """

    def __init__(self, master) -> None:
        self.frm = ttk.Frame(master, padding=5)

        # the calculator data
        self.calculator_data = CalculatorData(
            update_display=self.update_display,
            clear_display=self.clear_display,
            write_to_display=self.write_to_display,
            bell=self.frm.bell,
            vars_popup=self.vars_popup,
        )

        # scrolled text display
        self.display = scrolledtext.ScrolledText(
            self.frm,
            height=10,
            width=20,
        )
        # display is only enabled when we write to it
        self.display.configure(state="disabled")
        self.display.grid(row=0, column=0, sticky="news")
        self.frm.columnconfigure(0, weight=1)
        self.frm.rowconfigure(0, weight=1)

        # frame to hold the memory display
        self.memfrm = MemDispFrm(master=self.frm, calculator_data=self.calculator_data)
        self.frm.rowconfigure(1, weight=0)

        # frame to hold the buttons
        self.btnfrm = BtnDispFrm(master=self.frm, calculator_data=self.calculator_data)
        self.frm.rowconfigure(2, weight=1)

        self.frm.winfo_toplevel().bind(
            "<Escape>", lambda _: self.frm.winfo_toplevel().destroy()
        )

        self.frm.grid(column=0, row=0, sticky="news")

    def write_to_display(self, msg: str) -> None:
        """
        write_to_display - Write a message to the calculator display.

        Unlike update_display, this does not erase the last line of text.
        Text written will have newlines added before and after message.

        Parameters
        ----------
        msg : str
            Message to be written to the calculator display
        """

        self.display.configure(state="normal")
        self.display.insert("end", f"\n{msg}\n")
        # move to end
        self.display.see(tk.END)
        self.display.configure(state="disabled")

    def update_display(self) -> None:
        """
        update_display - Update the calculator display.

        This works be erasing the last line that displays the formula being
        input and replacing it with the most recent changes as returned by
        get_current_display_calc.
        """

        self.display.configure(state="normal")
        # replace last line
        self.display.delete("end-1l", "end")
        self.display.insert(
            "end", f"\n{self.calculator_data.get_current_display_calc()}"
        )
        # move to end
        self.display.see(tk.END)
        self.display.configure(state="disabled")

    def clear_display(self) -> None:
        """clear_display - Clear the display"""

        self.display.configure(state="normal")
        self.display.delete(1.0, "end")
        self.display.configure(state="disabled")

    def vars_popup(self) -> None:
        """varsPopup - Display a popup window with currently defined variables."""

        # get x and y location for popup
        x = self.frm.winfo_toplevel().winfo_x() + 10
        x = max(x, 10)
        y = self.frm.winfo_toplevel().winfo_y() + 175
        y = max(y, 10)

        self.varspopup = VarsPopup(x, y, self.calculator_data)


class MemDispFrm:
    """MemDispFrm - The memory display frame."""

    def __init__(self, master, calculator_data: CalculatorData) -> None:
        self.frm = ttk.Frame(master)

        self.memlbl = ttk.Label(self.frm, text="Memory:")
        self.memlbl.grid(row=0, column=0, sticky="e")

        self.mem_txt = ttk.Label(self.frm, textvariable=calculator_data.memval)
        self.mem_txt.grid(row=0, column=1, sticky="w")

        self.frm.columnconfigure(0, weight=0)
        self.frm.columnconfigure(1, weight=1)
        self.frm.rowconfigure(0, weight=0)

        self.frm.grid(column=0, row=1, sticky="news")


class BtnDispFrm:
    """BtnDispFrm - The calculator button display frame."""

    def __init__(self, master, calculator_data: CalculatorData) -> None:
        self.frm = ttk.Frame(master)
        self.calculator_data = calculator_data

        # each row with a different number of buttons is a different frame
        # this dict keeps track of all the frames
        self.button_frames: Dict[int, ttk.Frame] = {}

        # this frame contains only frames, so has only one column
        self.frm.columnconfigure(0, weight=1)

        # the keys in buttons are tuples of frame, row, column
        # sorting them ensures we process in the correct order
        for btn_loc, btn_info in sorted(buttons.items()):
            self.add_button(btn_loc, btn_info)

        self.frm.grid(column=0, row=2, sticky="news")

    def add_button(self, btn_loc: ButtonLocation, btn_info: ButtonInfo) -> None:
        """
        add_button - add a button to BtnDispFrm

        Parameters
        ----------
        button_loc : ButtonLocation
            Button location information
        button_info : ButtonInfo
            Button creation information
        """

        """
        at the paranoid level should proably validate that
        everything in button_loc and button_info is what it
        should be and not an injection attack
        """

        # if we have a new frame to add
        if btn_loc.btn_frame not in self.button_frames:

            self.button_frames[btn_loc.btn_frame] = ttk.Frame(self.frm)

            self.button_frames[btn_loc.btn_frame].grid(
                column=0,
                row=btn_loc.btn_frame,
                sticky="news",
            )

        # create the button
        if "command" in btn_info:
            cmd = lambda x=btn_info["command"]: self.calculator_data.process_button(x)
        else:
            cmd = lambda x=btn_info["label"]: self.calculator_data.process_button(
                "button", x
            )

        btnopts: dict = {"text": btn_info["label"], "command": cmd}
        if "style" in btn_info:
            btnopts["style"] = btn_info["style"]

        cur_btn = ttk.Button(self.button_frames[btn_loc.btn_frame], **btnopts)

        # add the button to the frame
        gridopts: dict = {
            "row": btn_loc.btn_row,
            "column": btn_loc.btn_column,
            "sticky": "news",
        }

        if "rowspan" in btn_info:
            gridopts["rowspan"] = btn_info["rowspan"]

        if "columnspan" in btn_info:
            gridopts["columnspan"] = btn_info["columnspan"]

        cur_btn.grid(**gridopts)

        # if this button is binding any events ...
        if "events" in btn_info:
            for be in btn_info["events"]:
                topwin = self.frm.winfo_toplevel()
                topwin.bind(be, lambda _, c=cur_btn: c.invoke())  # type: ignore

        # configure the weigts for the buttons
        self.button_frames[btn_loc.btn_frame].rowconfigure(
            btn_loc.btn_row,
            weight=1,
        )
        self.button_frames[btn_loc.btn_frame].columnconfigure(
            btn_loc.btn_column,
            weight=1,
        )
        # the weight of the subframe should be proportional to the
        # number of rows in the subframe
        self.frm.rowconfigure(
            btn_loc.btn_frame,
            weight=btn_loc.btn_row + 1,
        )


class VarsPopup:
    """VarsPopup - The popup window to display variables."""

    def __init__(self, x: int, y: int, calculator_data: CalculatorData) -> None:
        self.win = tk.Toplevel()

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
        self.add_variable_section("user variables", self.calculator_data.user_variables)

        # add buttons
        self.buttonfrm = VarsPopupTreeFrmButtons(master=self.frm, vptf=self)
        self.frm.rowconfigure(1, weight=0)

        # double click event to select a variable
        self.vars_tree.bind(
            "<Double-Button-1>", lambda _: self.buttonfrm.select_button.invoke()
        )

        self.frm.grid(row=0, column=0, sticky="news")

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


class VarsPopupTreeFrmButtons:
    """
    VarsPopupTreeFrmButtons - The frame with the buttons in the variables
    popup window.
    """

    def __init__(self, master, vptf: VarsPopupTreeFrm) -> None:
        self.frm = ttk.Frame(master)
        self.vptf = vptf

        self.edit_button = ttk.Button(
            self.frm,
            text="Edit User Variables",
            command=self.user_vars_edit,
        )
        self.edit_button.grid(row=0, column=0, columnspan=2)
        self.frm.columnconfigure(0, weight=1)
        self.frm.rowconfigure(0, weight=0)

        self.cancel_button = ttk.Button(
            self.frm,
            text="Cancel",
            command=self.frm.winfo_toplevel().destroy,
        )
        self.cancel_button.grid(row=1, column=0)
        self.frm.rowconfigure(1, weight=0)

        self.select_button = ttk.Button(
            self.frm,
            text="Select",
            command=self.user_vars_select,
        )
        self.select_button.grid(row=1, column=1)
        self.frm.columnconfigure(1, weight=1)

        top_win = self.frm.winfo_toplevel()
        top_win.bind("<Return>", lambda _: self.select_button.invoke())
        top_win.bind("<Escape>", lambda _: self.frm.winfo_toplevel().destroy())
        self.frm.grid(row=1, column=0, sticky="news")

    def user_vars_select(self) -> None:
        """user_vars_select - Return selected variable to the calculator."""

        vars_tree = self.vptf.vars_tree

        # if we have one of the variables selected
        # not on "default" or "user variables"
        if (
            vars_tree.selection()
            and vars_tree.selection()[0] not in vars_tree.get_children()
        ):
            self.vptf.calculator_data.button_press(
                vars_tree.item(vars_tree.selection()[0])["text"]
            )

        self.frm.winfo_toplevel().destroy()

    def user_vars_edit(self) -> None:
        """user_vars_edit - Popup window to edit the user variables."""

        x = self.frm.winfo_toplevel().winfo_x() + 10
        y = self.frm.winfo_toplevel().winfo_y() + 10
        self.editvars_win = UserVarsEditPopup(x, y, vptf=self.vptf)


class UserVarsEditPopup:
    """UserVarsEditPopup - Popup window to edit the user variables."""

    def __init__(self, x: int, y: int, vptf: VarsPopupTreeFrm) -> None:
        self.win = tk.Toplevel()

        self.win.focus_set()
        self.win.wm_title("Edit User Variables")

        self.win.focus_set()
        self.treefrm = UserVarsEditFrm(master=self.win, vptf=vptf)
        self.win.rowconfigure(0, weight=1)
        self.win.columnconfigure(0, weight=1)
        self.win.geometry("+%d+%d" % (x, y))


class UserVarsEditFrm:
    """UserVarsEditFrm - The frame with the user variables edit widgets"""

    def __init__(self, master, vptf: VarsPopupTreeFrm) -> None:
        self.frm = ttk.Frame(master)
        self.vptf = vptf

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
        self.uservars: dict[Tuple[int, int], ttk.Entry] = {}

        for k, v in self.vptf.calculator_data.user_variables.items():
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

        topwin = self.frm.winfo_toplevel()
        # cancel button
        self.cancelbtn = ttk.Button(self.frm, text="Cancel", command=topwin.destroy)
        self.cancelbtn.grid(row=1002, column=0)
        self.frm.rowconfigure(1002, weight=0)

        topwin.bind("<Escape>", lambda _: self.cancelbtn.invoke())

        # ok button
        self.okbtn = ttk.Button(
            self.frm,
            text="Ok",
            command=self.user_vars_edit_ok,
        )
        self.okbtn.grid(row=1002, column=1)

        topwin.bind("<Return>", lambda _: self.okbtn.invoke())

        # error message display
        self.errmsg = tk.StringVar(self.frm)
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

        currcalc = self.vptf.calculator_data.get_current_display_calc()
        if currcalc:
            # get the result
            self.vptf.calculator_data.calculate()
            result = self.vptf.calculator_data.get_current_input()

            # add result to a new row
            row = self.user_vars_edit_addrow()

            self.uservars[(row, 0)].delete(0, tk.END)
            self.uservars[(row, 0)].insert(0, "x")

            self.uservars[(row, 1)].delete(0, tk.END)
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
        tbox.insert(tk.INSERT, text)
        tbox.grid(row=rownum, column=colnum, sticky="news")
        self.uservars[(rownum, colnum)] = tbox
        self.frm.rowconfigure(rownum, weight=1)

        if colnum == 1:
            tbox.bind("<KeyRelease>", self.format_number)

    def format_number(self, event: tk.Event) -> None:
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
            event.widget.delete(0, tk.END)
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
        self.vptf.calculator_data.user_variables = newuservars

        # close this window
        self.frm.winfo_toplevel().destroy()

        # rebuild the varspopup
        self.vptf.frm.winfo_toplevel().destroy()
        self.vptf.calculator_data.vars_popup()

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
