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
