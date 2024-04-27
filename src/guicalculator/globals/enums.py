"""
enums.py - Enumerations needed by more than one module.
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


from enum import Enum, StrEnum, unique

from .functionstype import FunctionsType


@unique
class CalculatorSymbols(StrEnum):
    """Enum representing calculator math operators like + or -"""

    NOSYMBOL = ""
    OPENPAREN = "("
    CLOSEPAREN = ")"
    DIVISION = "/"
    MULTIPLICATION = "*"
    SUBTRACTION = "-"
    ADDITION = "+"
    SQUARE = "** 2"
    EXPONENTIATION = "**"


@unique
class CalculatorFunctions(FunctionsType, Enum):
    """Enum that represent functions used by the calculator like square root"""

    NOFUNCTION = ("", "")
    INVERSION = ("1/", "1/")
    SQUAREROOT = ("sqrt", "Decimal.sqrt")


@unique
class CalculatorCommands(StrEnum):
    """Enum that represent command strings used by the calculator"""

    NOCOMMAND = ""
    BASICBUTTON = "button"
    BACKSPACE = "backspace"
    CALCULATE = "calculate"
    CLEARALL = "clearAll"
    CLEARVALUE = "clearValue"
    INVERSENUMBER = "inverseNumber"
    INVERTSIGN = "invertSign"
    MEMADD = "memAdd"
    MEMCLEAR = "memClear"
    MEMRECALL = "memRecall"
    MEMSTORE = "memStore"
    MEMSUBTRACT = "memSubtract"
    MEMSWAP = "memSwap"
    ROOTNUMBER = "rootNumber"
    SQUARENUMBER = "squareNumber"
    VARSPOPUP = "varsPopup"
    XTOTHEY = "xToTheY"


@unique
class ButtonStyles(StrEnum):
    """Enum that represent styles used by calculator buttons"""

    NOSTYLE = ""
    NUMBER = "number.TButton"
    ORANGE = "orange.TButton"
    RED = "red.TButton"
    MEMORY = "memory.TButton"
    MATHOP = "mathop.TButton"


@unique
class TkEvents(StrEnum):
    """Enum that represent events bound by Tk widgets"""

    NOEVENT = ""
    BACKSPACE = "<BackSpace>"
    UPPER_C = "<KeyPress-C>"
    LOWER_C = "<KeyPress-c>"
    OPENPAREN = "<KeyPress-(>"
    CLOSEPAREN = "<KeyPress-)>"
    DIVISION = "<KeyPress-/>"
    MULTIPLICATION = "<KeyPress-*>"
    SUBTRACTION = "<KeyPress-minus>"
    ADDITION = "<KeyPress-+>"
    NUM_1 = "<KeyPress-1>"
    NUM_2 = "<KeyPress-2>"
    NUM_3 = "<KeyPress-3>"
    NUM_4 = "<KeyPress-4>"
    NUM_5 = "<KeyPress-5>"
    NUM_6 = "<KeyPress-6>"
    NUM_7 = "<KeyPress-7>"
    NUM_8 = "<KeyPress-8>"
    NUM_9 = "<KeyPress-9>"
    NUM_0 = "<KeyPress-0>"
    DECIMALPOINT = "<KeyPress-.>"
    EQUALS = "<KeyPress-=>"
    RETURN = "<Return>"
    ESCAPE = "<Escape>"
    DOUBLECLICK = "<Double-Button-1>"
    KEYRELEASE = "<KeyRelease>"


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
