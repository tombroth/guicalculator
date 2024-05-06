"""
backspace.py - The backspace function.
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

from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData
from .types import _CalcStringFunction, _CalcStringNumber, _CalcStringString


@object_wrapper
def backspace(self: CalculatorData) -> None:
    """backspace - Erase last character from number being input."""

    # if we have a number being input, remove last digit
    if self._current_input:
        self._current_input = self._current_input[:-1]

    # if we have a function in the last place
    elif self._current_calc and isinstance(self._current_calc[-1], _CalcStringFunction):
        last = self._current_calc[-1]._param

        # if it is a nested function or a function with a variable parameter, unnest
        if isinstance(last, (_CalcStringFunction, _CalcStringString)):
            self._current_calc[-1] = last

        # if it is a single number parameter
        elif isinstance(last, _CalcStringNumber):
            self._current_input = last.get_disp().replace(",", "")
            del self._current_calc[-1]

        # unexpected parameter(s)
        else:
            self.bell()

    # if we have a string (a variable, math operator, etc), remove it
    elif self._current_calc and isinstance(self._current_calc[-1], _CalcStringString):
        del self._current_calc[-1]

    # if we have a number, put it in _current_input and remove last digit
    elif self._current_calc and isinstance(self._current_calc[-1], _CalcStringNumber):
        self._current_input = self._current_calc[-1].get_disp().replace(",", "")[:-1]
        del self._current_calc[-1]

    # if we have nothing (or unexpected list member), ring the bell
    else:
        self.bell()

    self.update_display()
