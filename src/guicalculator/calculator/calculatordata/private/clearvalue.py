from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData


@object_wrapper
def clear_value(self: CalculatorData) -> None:
    """
    clear_value - Clear the current number input, or if that is empty
    then clear the current calculation.
    """

    if self._current_input:
        self._current_input = ""
    else:
        self._current_calc = []

    self.update_display()
