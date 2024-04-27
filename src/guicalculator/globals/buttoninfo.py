"""
buttoninfo.py - Class ButtonInfo, information needed to create a button.
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


from dataclasses import dataclass
from typing import Optional

from .enums import ButtonLabels, ButtonStyles, CalculatorCommands, TkEvents


@dataclass
class ButtonInfo:
    """
    ButtonInfo - Information needed to create a button on the calculator.

    Parameters
    ----------
    TypedDict : A dictionary consisting of:
        label : ButtonLabels | int
            Mandatory. The button text. Number buttons should be int,
            everything else ButtonLabels.
        command : Optional[CalculatorCommands]
            Optional. Which command to execute. No command is needed for
            basic number and math operators. Commands are decoded by the
            processbutton funciton in calculatordata.py.
        style : Optional[ButtonStyles]
            Optional. Style information for the button. Styles are found
            in CalcStyle in guicalculator.py.
        rowspan : Optional[int]
            Optional. This is the rowspan parameter of the grid call.
        columnspan : Optional[int]
            Optional. This is the columnspan parameter of the grid call.
        events : Optional[List[TkEvents]]
            Optional. This is a list of events bound to this button.invoke,
            bound at winfo_toplevel.
    """

    label: ButtonLabels | int
    command: Optional[CalculatorCommands] = CalculatorCommands.NOCOMMAND
    style: Optional[ButtonStyles] = ButtonStyles.NOSTYLE
    rowspan: Optional[int] = None
    columnspan: Optional[int] = None
    events: Optional[list[TkEvents]] = None
