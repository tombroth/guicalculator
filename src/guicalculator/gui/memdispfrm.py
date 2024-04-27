"""
memdispfrm.py - This is the gui calculator memory display frame.
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
