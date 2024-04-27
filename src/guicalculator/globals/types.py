"""
types.py - Types needed by more than one module.
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

from decimal import Decimal
from typing import NamedTuple, NewType

VariablesType = NewType("VariablesType", dict[str, Decimal])
"""Type to store varaibles and values for the parser: dict[str, Decimal]"""


class ButtonLocation(NamedTuple):
    """
    ButtonLocation - Where to locate a button on the calculator

    Parameters
    ----------
    NamedTuple : A tuple consisting of:
        btnfrm : int
            This indicates which sub-frame of the button frame to place the
            button into. Subframes are used to group rows with the same
            number of buttons. The first subframe is 0.
        btnrow : int
            This indicates which row in the sub-frame the button is placed
            on. The first row of a new sub-frame is 0.
        btncol : int
            This indicates which column in the row the button is placed on.
            The first column of a new sub-frame is 0.
    """

    btn_frame: int
    btn_row: int
    btn_column: int
