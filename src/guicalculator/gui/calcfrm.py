"""
calcfrm.py - This is the gui calculator main frame. All calculator widgets
are in this frame.
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

from tkinter import END, scrolledtext, ttk

from ..calculator import CalculatorData
from ..globals import TkEvents
from .btndispfrm import BtnDispFrm
from .memdispfrm import MemDispFrm
from .varspopup import VarsPopup


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
            TkEvents.ESCAPE, lambda _: self.frm.winfo_toplevel().destroy()
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
        self.display.see(END)
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
        self.display.see(END)
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
