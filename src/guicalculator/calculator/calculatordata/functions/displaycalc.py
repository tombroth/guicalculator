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
