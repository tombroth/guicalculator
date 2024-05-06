from decimal import Decimal

from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData


@object_wrapper
def get_current_input(self: CalculatorData) -> Decimal | None:
    """
    get_current_input - Get current number input as a Decimal.

    Returns
    -------
    Decimal | None
        Decimal version of the number currently being input, None if no
        number is currently being input.
    """

    if self._current_input:
        return Decimal(self._current_input)
    else:
        return None
