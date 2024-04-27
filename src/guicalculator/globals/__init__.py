"""guicalculator/gui - This is the directory with all the tkinter widgets for the calculator


The files in this directory:

    buttoninfo.py - dataclass ButtonInfo

    constants.py - Constants

    enums.py - Enumerations

    functionstype.py - dataclass FunctionsType

    types.py - Types
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

from .buttoninfo import ButtonInfo
from .constants import DEFAULT_VARIABLES, NORMALIZE_FORM, PI
from .enums import (
    ButtonLabels,
    ButtonStyles,
    CalculatorCommands,
    CalculatorFunctions,
    CalculatorSymbols,
    TkEvents,
)
from .functionstype import FunctionsType
from .types import ButtonLocation, VariablesType

__all__ = [
    "ButtonInfo",
    "ButtonLabels",
    "ButtonLocation",
    "ButtonStyles",
    "CalculatorCommands",
    "CalculatorFunctions",
    "CalculatorSymbols",
    "DEFAULT_VARIABLES",
    "FunctionsType",
    "NORMALIZE_FORM",
    "PI",
    "TkEvents",
    "VariablesType",
]
