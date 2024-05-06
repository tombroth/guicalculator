"""
updatecalc.py - The update_current_calc function updates the current calculation.
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

from ....globals import CalculatorFunctions, CalculatorSymbols, FunctionsType
from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData
from .getnumfncsym import get_num_fnc_sym
from .getuservarnames import get_user_variable_names
from .types import (
    _CalcStringBase,
    _CalcStringFunction,
    _CalcStringNumber,
    _CalcStringString,
)
from .validatesymfunc import validate_symbol_and_func


@object_wrapper
def update_current_calc(
    self: CalculatorData,
    symbol: str = "",
    func: FunctionsType = CalculatorFunctions.NOFUNCTION,
) -> None:
    """
    update_current_calc - Update the current calculation being input.

    Notes
    -----
    As a side effect, will round the number currently being input to the
    precision in the Decimal context.

    Parameters
    ----------
    symbol : str, optional
        Optional string to be added to the end of the calculation. Normally
        will be blank or a mathematical operator, by default "".
    func : FunctionsType, optional
        Optional dataclass containing function to be added, by default NOFUNCTION.
    """

    validate_symbol_and_func(self, symbol, func)

    num, fnc, sym = get_num_fnc_sym(self, symbol, func, True)

    # check to see if we need any implied multiplications

    mul_between = None  # the multiplication symbol between num and sym if needed
    mul_before = None  # the multiplication symbol before (num, func, sym) if needed

    # is the symbol a variable or open parenthesis
    is_var_or_paren = sym and sym.get_disp() in [
        CalculatorSymbols.OPENPAREN.value
    ] + get_user_variable_names(self)

    if num or fnc or is_var_or_paren:

        # only possibility is a number and either paren or variable
        # function would consume number if available
        if num and is_var_or_paren:
            mul_between = _CalcStringString(CalculatorSymbols.MULTIPLICATION)

        if self._current_calc:
            last = self._current_calc[-1]

            # if the last thing in the calculation is a number, function, close paren or variable
            if isinstance(last, (_CalcStringNumber, _CalcStringFunction)) or (
                last.get_disp()
                in [CalculatorSymbols.CLOSEPAREN.value] + get_user_variable_names(self)
            ):
                mul_before = _CalcStringString(CalculatorSymbols.MULTIPLICATION)

    tmpcalc: list[_CalcStringBase] = [
        c for c in [mul_before, num, mul_between, fnc, sym] if c != None
    ]

    self._current_calc += tmpcalc

    self._current_input = ""

    self.update_display()
