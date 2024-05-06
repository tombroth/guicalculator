from decimal import Decimal

from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData


@object_wrapper
def get_current_memory(self: CalculatorData) -> Decimal | None:
    """
    get_current_memory - Get the current value stored in memory as a Decimal.

    Returns
    -------
    Decimal | None
        Decimal version of the value stored in memory, or None if no value is
        currently stored in memory.
    """

    mem = self._memval.get().replace(",", "")
    if mem:
        return Decimal(mem)
    else:
        return None
