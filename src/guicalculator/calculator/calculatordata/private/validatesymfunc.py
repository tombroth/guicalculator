"""
validatesymfunc.py - The validate_symbol_and_func function validates the 
symbol and/or function being input.
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
from .getuservarnames import get_user_variable_names


@object_wrapper
def validate_symbol_and_func(
    self: CalculatorData, symbol: str, func: FunctionsType
) -> None:
    """
    validate_symbol_and_func - Validate that symbol and func are valid.

    Parameters
    ----------
    symbol : str
        String to be added to the end of the calculation.
    func : FunctionsType
        Dataclass containing function to be added.

    Raises
    ------
    ValueError
        Used for custom errors, message indicates what the specific error was.
    """

    # initialize lists of valid symbols and functions
    valid_symbols = [cs.value for cs in CalculatorSymbols] + get_user_variable_names(
        self
    )

    valid_funcs = [cf for cf in CalculatorFunctions]

    # validate symbol
    if symbol:
        if not isinstance(symbol, str):
            raise ValueError(f"Symbol is wrong data type: {symbol!r}")

        if symbol not in valid_symbols:
            raise ValueError(f"Invalid symbol: {symbol!r}")

    # validate function
    if func:
        if not isinstance(func, FunctionsType):
            raise ValueError(f"Function is not FunctionsType: {func!r}: {type(func)}")

        if func not in valid_funcs:
            raise ValueError(f"Invalid function: {func!r}")

        if symbol and func != CalculatorFunctions.NOFUNCTION:
            raise ValueError(
                f"Cannot specify both symbol and function: {symbol}, {func}"
            )
