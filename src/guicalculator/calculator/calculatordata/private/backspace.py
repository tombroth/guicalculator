from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData
from .types import _CalcStringFunction, _CalcStringNumber, _CalcStringString


@object_wrapper
def backspace(self: CalculatorData) -> None:
    """backspace - Erase last character from number being input."""

    # if we have a number being input, remove last digit
    if self._current_input:
        self._current_input = self._current_input[:-1]

    # if we have a function in the last place
    elif self._current_calc and isinstance(self._current_calc[-1], _CalcStringFunction):
        last = self._current_calc[-1]._param

        # if it is a nested function or a function with a variable parameter, unnest
        if isinstance(last, (_CalcStringFunction, _CalcStringString)):
            self._current_calc[-1] = last

        # if it is a single number parameter
        elif isinstance(last, _CalcStringNumber):
            self._current_input = last.get_disp().replace(",", "")
            del self._current_calc[-1]

        # unexpected parameter(s)
        else:
            self.bell()

    # if we have a string (a variable, math operator, etc), remove it
    elif self._current_calc and isinstance(self._current_calc[-1], _CalcStringString):
        del self._current_calc[-1]

    # if we have a number, put it in _current_input and remove last digit
    elif self._current_calc and isinstance(self._current_calc[-1], _CalcStringNumber):
        self._current_input = self._current_calc[-1].get_disp().replace(",", "")[:-1]
        del self._current_calc[-1]

    # if we have nothing (or unexpected list member), ring the bell
    else:
        self.bell()

    self.update_display()
