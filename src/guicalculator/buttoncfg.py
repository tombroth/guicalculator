"""
buttoncfg.py - This file contains the buttons dictionary that defines the 
calculator buttons.

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
from enum import StrEnum, unique
from typing import List, NamedTuple, Optional

from .globals import ButtonStyles, CalculatorCommands, CalculatorSymbols, TkEvents


@unique
class ButtonLabels(StrEnum):
    """Enum that represent the button labels"""

    NOLABEL = ""
    BACKSPACE = "\u232B"
    CLEARENTRY = "CE"
    ALLCLEAR = "AC"

    MEMORYCLEAR = "MClr"
    MEMORYRECALL = "MRcl"
    MEMORYSTORE = "MSto"
    MEMORYSWAP = "MSwp"
    MEMORYADD = "M+"
    MEMORYSUBTRACT = "M-"

    INVERSION = "1/x"
    XSQUARED = "x\u00b2"
    SQUAREROOTX = "\u221ax"
    XTOTHEY = "x ** y"

    VARIABLESPOPUP = "vars..."
    OPENPAREN = CalculatorSymbols.OPENPAREN.value
    CLOSEPAREN = CalculatorSymbols.CLOSEPAREN.value
    DIVISION = CalculatorSymbols.DIVISION.value
    MULTIPLICATION = CalculatorSymbols.MULTIPLICATION.value
    SUBTRACTION = CalculatorSymbols.SUBTRACTION.value
    ADDITION = CalculatorSymbols.ADDITION.value

    INVERTSIGN = "+/-"
    DECIMALPOINT = "."
    EQUALS = "="


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
    events: Optional[List[TkEvents]] = None


# The calculator buttons
buttons: dict[ButtonLocation, ButtonInfo] = {
    ButtonLocation(0, 0, 0): ButtonInfo(
        label=ButtonLabels.BACKSPACE,
        command=CalculatorCommands.BACKSPACE,
        style=ButtonStyles.RED,
        events=[TkEvents.BACKSPACE],
    ),
    ButtonLocation(0, 0, 1): ButtonInfo(
        label=ButtonLabels.CLEARENTRY,
        command=CalculatorCommands.CLEARVALUE,
        style=ButtonStyles.RED,
        events=[TkEvents.UPPER_C, TkEvents.LOWER_C],
    ),
    ButtonLocation(0, 0, 2): ButtonInfo(
        label=ButtonLabels.ALLCLEAR,
        command=CalculatorCommands.CLEARALL,
        style=ButtonStyles.RED,
    ),
    ButtonLocation(1, 0, 0): ButtonInfo(
        label=ButtonLabels.MEMORYCLEAR,
        command=CalculatorCommands.MEMCLEAR,
        style=ButtonStyles.MEMORY,
    ),
    ButtonLocation(1, 0, 1): ButtonInfo(
        label=ButtonLabels.MEMORYRECALL,
        command=CalculatorCommands.MEMRECALL,
        style=ButtonStyles.MEMORY,
    ),
    ButtonLocation(1, 0, 2): ButtonInfo(
        label=ButtonLabels.MEMORYSTORE,
        command=CalculatorCommands.MEMSTORE,
        style=ButtonStyles.MEMORY,
    ),
    ButtonLocation(1, 0, 3): ButtonInfo(
        label=ButtonLabels.MEMORYSWAP,
        command=CalculatorCommands.MEMSWAP,
        style=ButtonStyles.MEMORY,
    ),
    ButtonLocation(1, 0, 4): ButtonInfo(
        label=ButtonLabels.MEMORYADD,
        command=CalculatorCommands.MEMADD,
        style=ButtonStyles.MEMORY,
    ),
    ButtonLocation(1, 0, 5): ButtonInfo(
        label=ButtonLabels.MEMORYSUBTRACT,
        command=CalculatorCommands.MEMSUBTRACT,
        style=ButtonStyles.MEMORY,
    ),
    ButtonLocation(2, 0, 0): ButtonInfo(
        label=ButtonLabels.INVERSION,
        command=CalculatorCommands.INVERSENUMBER,
    ),
    ButtonLocation(2, 0, 1): ButtonInfo(
        label=ButtonLabels.XSQUARED,
        command=CalculatorCommands.SQUARENUMBER,
    ),
    ButtonLocation(2, 0, 2): ButtonInfo(
        label=ButtonLabels.SQUAREROOTX,
        command=CalculatorCommands.ROOTNUMBER,
    ),
    ButtonLocation(2, 0, 3): ButtonInfo(
        label=ButtonLabels.XTOTHEY,
        command=CalculatorCommands.XTOTHEY,
    ),
    ButtonLocation(2, 1, 0): ButtonInfo(
        label=ButtonLabels.VARIABLESPOPUP,
        command=CalculatorCommands.VARSPOPUP,
    ),
    ButtonLocation(2, 1, 1): ButtonInfo(
        label=ButtonLabels.OPENPAREN,
        events=[TkEvents.OPENPAREN],
    ),
    ButtonLocation(2, 1, 2): ButtonInfo(
        label=ButtonLabels.CLOSEPAREN,
        events=[TkEvents.CLOSEPAREN],
    ),
    ButtonLocation(2, 1, 3): ButtonInfo(
        label=ButtonLabels.DIVISION,
        style=ButtonStyles.MATHOP,
        events=[TkEvents.DIVISION],
    ),
    ButtonLocation(2, 2, 0): ButtonInfo(
        label=7,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.NUM_7],
    ),
    ButtonLocation(2, 2, 1): ButtonInfo(
        label=8,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.NUM_8],
    ),
    ButtonLocation(2, 2, 2): ButtonInfo(
        label=9,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.NUM_9],
    ),
    ButtonLocation(2, 2, 3): ButtonInfo(
        label=ButtonLabels.MULTIPLICATION,
        style=ButtonStyles.MATHOP,
        events=[TkEvents.MULTIPLICATION],
    ),
    ButtonLocation(2, 3, 0): ButtonInfo(
        label=4,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.NUM_4],
    ),
    ButtonLocation(2, 3, 1): ButtonInfo(
        label=5,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.NUM_5],
    ),
    ButtonLocation(2, 3, 2): ButtonInfo(
        label=6,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.NUM_6],
    ),
    ButtonLocation(2, 3, 3): ButtonInfo(
        label=ButtonLabels.SUBTRACTION,
        style=ButtonStyles.MATHOP,
        events=[TkEvents.SUBTRACTION],
    ),
    ButtonLocation(2, 4, 0): ButtonInfo(
        label=1,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.NUM_1],
    ),
    ButtonLocation(2, 4, 1): ButtonInfo(
        label=2,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.NUM_2],
    ),
    ButtonLocation(2, 4, 2): ButtonInfo(
        label=3,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.NUM_3],
    ),
    ButtonLocation(2, 4, 3): ButtonInfo(
        label=ButtonLabels.ADDITION,
        style=ButtonStyles.MATHOP,
        events=[TkEvents.ADDITION],
    ),
    ButtonLocation(2, 5, 0): ButtonInfo(
        label=ButtonLabels.INVERTSIGN,
        command=CalculatorCommands.INVERTSIGN,
        style=ButtonStyles.NUMBER,
    ),
    ButtonLocation(2, 5, 1): ButtonInfo(
        label=0,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.NUM_0],
    ),
    ButtonLocation(2, 5, 2): ButtonInfo(
        label=ButtonLabels.DECIMALPOINT,
        style=ButtonStyles.NUMBER,
        events=[TkEvents.DECIMALPOINT],
    ),
    ButtonLocation(2, 5, 3): ButtonInfo(
        label=ButtonLabels.EQUALS,
        command=CalculatorCommands.CALCULATE,
        style=ButtonStyles.ORANGE,
        events=[TkEvents.EQUALS, TkEvents.RETURN],
    ),
}
