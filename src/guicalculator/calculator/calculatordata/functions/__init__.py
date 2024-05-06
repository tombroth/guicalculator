"""
guicalculator/calculator/calculatordata/functions - Calculator functions used 
by the user interface.

The files in this directory:

    displaycalc.py - The get_current_display_calc function

    evalcalc.py - The get_current_eval_calc function

    getuservar.py - The get_user_variables function

    processbutton.py - The process_button function

    setuservar.py - The set_user_variables function
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

from .displaycalc import get_current_display_calc
from .evalcalc import get_current_eval_calc
from .getuservar import get_user_variables
from .processbutton import process_button
from .setuservar import set_user_variables

__all__ = [
    "get_current_display_calc",
    "get_current_eval_calc",
    "get_user_variables",
    "process_button",
    "set_user_variables",
]
