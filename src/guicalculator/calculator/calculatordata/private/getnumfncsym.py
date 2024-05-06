"""
getnumfncsym.py - The get_num_fnc_sym function returns the _CalcStringBase 
representations of current input, passed in function and/or passed in symbol.
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

from ....globals import CalculatorFunctions, FunctionsType
from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData
from .getcurinpt import get_current_input
from .getuservarnames import get_user_variable_names
from .types import _CalcStringFunction, _CalcStringNumber, _CalcStringString


@object_wrapper
def get_num_fnc_sym(
    self: CalculatorData,
    symbol: str,
    func: FunctionsType,
    remove_parameter: bool = False,
) -> tuple[
    _CalcStringNumber | None, _CalcStringFunction | None, _CalcStringString | None
]:
    """
    get_num_fnc_sym - internal function to convert _current_input, symbol,
    and func into their _CalcStringBase representations. Used by the
    functions that display or update _current_calc.

    Will validate that parameters are correct type but assumes that symbol
    and func have already passed through validate_symbol_and_func.

    Parameters
    ----------
    symbol : str
        String to be added to the end of the calculation.
    func : FunctionsType
        Dataclass containing function to be added.
    remove_parameter : bool, optional
        If a parameter from _current_calc is needed for func, is it
        okay to remove it from _current_calc, by default False

    Returns
    -------
    tuple[ _CalcStringNumber | None, _CalcStringFunction | None, _CalcStringString | None ]
        The _CalcStringBase representations of the number, function and symbol

    Raises
    ------
    TypeError
        Used for custom errors, message indicates what the specific error was.
    """

    # basic validation of parameters
    if symbol and not isinstance(symbol, str):
        raise TypeError(f"Symbol is not correct type")
    if func and not isinstance(func, FunctionsType):
        raise TypeError(f"Function is not correct type")
    # no need to check remove_parameter, Python will cast anything to bool

    inpt, infnc, sym = None, None, None

    # if we are inputting a number
    if self._current_input:
        inpt = _CalcStringNumber(
            get_current_input(self),
            (str(self._current_input)[-1] == "."),
        )

    # if we are inputting a symbol like + or )
    if symbol:
        sym = _CalcStringString(symbol)

    # if we are inputting a function
    if func and func != CalculatorFunctions.NOFUNCTION:
        # if number being input
        if inpt:
            infnc = _CalcStringFunction(func, inpt)
            inpt = None

        # if number, variable, or function was just input
        elif self._current_calc and (
            (
                isinstance(
                    self._current_calc[-1], (_CalcStringNumber, _CalcStringFunction)
                )
            )
            or (self._current_calc[-1].get_disp() in get_user_variable_names(self))
        ):
            infnc = _CalcStringFunction(func, self._current_calc[-1])
            if remove_parameter:
                self._current_calc = self._current_calc[:-1]

        else:
            raise TypeError("No argument for function")

    return inpt, infnc, sym
