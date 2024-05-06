from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData


@object_wrapper
def clear_all(self: CalculatorData) -> None:
    """
    clear_all - Clear the current number being input, the current
    calculation, and the display. Does not clear the value in memory.
    """

    self.clear_display()

    self._current_calc = []
    self._current_input = ""

    self.update_display()
