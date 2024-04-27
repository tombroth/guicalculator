"""
btndispfrm.py - This is the gui calculator button display frame.
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

from ..buttoncfg import ButtonInfo, ButtonLocation, buttons
from ..calculator import CalculatorData
from ..globals import CalculatorCommands


class BtnDispFrm:
    """BtnDispFrm - The calculator button display frame."""

    def __init__(self, master, calculator_data: CalculatorData) -> None:
        self.frm = ttk.Frame(master)
        self.calculator_data = calculator_data

        # each row with a different number of buttons is a different frame
        # this dict keeps track of all the frames
        self.button_frames: dict[int, ttk.Frame] = {}

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
        if btn_info.command:
            cmd = lambda x=btn_info.command: self.calculator_data.process_button(x)
        else:
            cmd = lambda x=btn_info.label: self.calculator_data.process_button(
                CalculatorCommands.BASICBUTTON, x
            )

        btnopts: dict = {"text": btn_info.label, "command": cmd}

        if btn_info.style:
            btnopts["style"] = btn_info.style

        cur_btn = ttk.Button(self.button_frames[btn_loc.btn_frame], **btnopts)

        # add the button to the frame
        gridopts: dict = {
            "row": btn_loc.btn_row,
            "column": btn_loc.btn_column,
            "sticky": "news",
        }

        if btn_info.rowspan:
            gridopts["rowspan"] = btn_info.rowspan

        if btn_info.columnspan:
            gridopts["columnspan"] = btn_info.columnspan

        cur_btn.grid(**gridopts)

        # if this button is binding any events ...
        if btn_info.events:
            for be in btn_info.events:
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
