"""guicalculator/calculator - This is the directory with all the tkinter widgets for the calculator


The files in this directory:

    evaluate_calculation.py - The parser function, evaluate_calculation

    numtostr.py - The Decimal number to string function

    strtodecimal.py - The string to Decimal function
    
    validate_user_var.py - The user variable validation function

The subdirectories in this directory:

    calculatordata - The CalculatorData class with related functions.
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

from .calculatordata import CalculatorData
from .calculatordata.functions import (
    get_current_display_calc,
    get_current_eval_calc,
    get_user_variables,
    process_button,
    set_user_variables,
)
from .evaluate_calculation import evaluate_calculation
from .logwrapper import (
    enable_gui_logging,
    gui_object_wrapper,
    logerror,
    object_wrapper,
    plain_wrapper,
)
from .numtostr import numtostr
from .strtodecimal import strtodecimal
from .validate_user_var import validate_user_var, validate_user_vars

__all__ = [
    "CalculatorData",
    "enable_gui_logging",
    "evaluate_calculation",
    "get_current_display_calc",
    "get_current_eval_calc",
    "get_user_variables",
    "gui_object_wrapper",
    "logerror",
    "numtostr",
    "object_wrapper",
    "plain_wrapper",
    "process_button",
    "set_user_variables",
    "strtodecimal",
    "validate_user_var",
    "validate_user_vars",
]
