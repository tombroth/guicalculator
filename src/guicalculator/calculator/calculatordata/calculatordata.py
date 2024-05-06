"""
calculatordata.py - The CalculatorData class, stores calculator state.
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

from tkinter import StringVar
from typing import Callable

from ...globals import VariablesType
from .private.types import _CalcStringBase


class CalculatorData:
    """CalculatorData - Data and functions used by the calculator"""

    # data used by the calculator
    _current_calc: list[_CalcStringBase] = []  # the current calculation
    _current_input: str = ""  # the current number input

    _user_variables: VariablesType = VariablesType({})  # user defined variables

    def __init__(
        self,
        update_display: Callable[[], None],
        clear_display: Callable[[], None],
        write_to_display: Callable[[str], None],
        bell: Callable[[], None],
        vars_popup: Callable[[], None],
        memval: StringVar,
    ) -> None:
        self.update_display = update_display
        self.clear_display = clear_display
        self.write_to_display = write_to_display
        self.bell = bell
        self.vars_popup = vars_popup
        self._memval = memval
