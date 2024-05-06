"""
buttoncfg.py - This file contains the buttons dictionary that defines the 
calculator buttons.
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


from .globals import (
    ButtonInfo,
    ButtonLabels,
    ButtonLocation,
    ButtonStyles,
    CalculatorCommands,
    TkEvents,
)

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
        command=CalculatorCommands.NEGATE,
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
