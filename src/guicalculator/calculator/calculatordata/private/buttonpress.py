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
