"""
displaycalc.py - The get_current_display_calc function, returns the display 
version of the current calculation.
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
from ..private.getnumfncsym import get_num_fnc_sym
from ..private.types import _CalcStringBase
from ..private.validatesymfunc import validate_symbol_and_func


@object_wrapper
def get_current_display_calc(
    self: CalculatorData,
    symbol: str = "",
    func: FunctionsType = CalculatorFunctions.NOFUNCTION,
) -> str:
    """
    get_current_display_calc - Get the current displayed calculation.

    Get the current displayed calculation, including current number input
    and optional mathematical operator.

    Parameters
    ----------
    symbol : str, optional
        Optional string to be added to the end of the calculation. Normally
        will be blank or a mathematical operator, by default "".
    func : FunctionsType, optional
        Optional dataclass containing function to be added, by default NOFUNCTION.

    Returns
    -------
    str
        The current displayed calculation.
    """

    validate_symbol_and_func(self, symbol, func)

    num, fnc, sym = get_num_fnc_sym(self, symbol, func)

    tmpcalc: list[_CalcStringBase] = [c for c in [num, fnc, sym] if c != None]

    return_value = " ".join(e.get_disp() for e in self._current_calc + tmpcalc).strip()
    return return_value
