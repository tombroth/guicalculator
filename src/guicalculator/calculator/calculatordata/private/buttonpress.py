"""
buttonpress.py - The button_press function - handles simple buttons.
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

from ....globals import CalculatorSymbols
from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData
from .getuservarnames import get_user_variable_names
from .types import _CalcStringFunction, _CalcStringNumber, _CalcStringString
from .updatecalc import update_current_calc


@object_wrapper
def button_press(self: CalculatorData, symbol: str | int) -> None:
    """
    button_press - Handles simple button presses.

    Handles simple button presses that just add to the current formula. For
    example, a digit (passed as int, not str), ".", "+", "-", etc. Does not
    handle complex things like manipulating the value stored in memory.

    Notes
    -----
    As a side effect, will round the number currently being input to the
    precision in the Decimal context if symbol is not a digit or decimal
    point.

    Parameters
    ----------
    symbol : str | int
        The digit or mathematical operator being processed.
    """

    if isinstance(symbol, int):

        # if it is the first digit
        if not self._current_input:

            # and the previous thing on calculation is a number, function, variable, or close paren
            if self._current_calc and (
                isinstance(
                    self._current_calc[-1],
                    (_CalcStringNumber, _CalcStringFunction),
                )
                or self._current_calc[-1].get_disp()
                in get_user_variable_names(self) + [CalculatorSymbols.CLOSEPAREN.value]
            ):
                # add an explicit multiplication
                self._current_calc.append(
                    _CalcStringString(CalculatorSymbols.MULTIPLICATION)
                )

        self._current_input += str(symbol)
        self.update_display()

    elif symbol == ".":
        if symbol in self._current_input:
            self.bell()
            return

        self._current_input = (self._current_input or "0") + symbol
        self.update_display()

    else:
        update_current_calc(self, symbol)
