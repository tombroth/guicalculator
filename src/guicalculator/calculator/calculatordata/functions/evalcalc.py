from ....globals import CalculatorFunctions, FunctionsType
from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData
from ..private.getnumfncsym import get_num_fnc_sym
from ..private.types import _CalcStringBase
from ..private.validatesymfunc import validate_symbol_and_func


@object_wrapper
def get_current_eval_calc(
    self: CalculatorData,
    symbol: str = "",
    func: FunctionsType = CalculatorFunctions.NOFUNCTION,
) -> str:
    """
    get_current_eval_calc - Get the current calculation to be evaluated.

    Get the current calculation to be evaluated, including current number
    input and optional mathematical operator. The primary difference from
    get_current_display_calc is that the number inputs are surrounded by
    calls to Decimal to convert int and float inputs into Decimal to avoid
    decimal to binary and back to decimal rounding errors. In other words
    0.3 - 0.2 should be 0.1, not 0.09999999999999998.

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
        The calculation to be evaluated.
    """

    validate_symbol_and_func(self, symbol, func)

    num, fnc, sym = get_num_fnc_sym(self, symbol, func)

    tmpcalc: list[_CalcStringBase] = [c for c in [num, fnc, sym] if c != None]

    return_value = " ".join(e.get_eval() for e in self._current_calc + tmpcalc).strip()
    return return_value
