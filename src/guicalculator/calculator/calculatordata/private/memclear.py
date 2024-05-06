from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData


@object_wrapper
def memory_clear(self: CalculatorData) -> None:
    """memory_clear - Clear the value stored in memory"""

    self._memval.set("")
