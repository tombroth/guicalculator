from tkinter import StringVar
from typing import Callable

from ...globals import VariablesType
from .private.types import _CalcStringBase


class CalculatorData:
    """CalculatorData - Data and functions used by the calculator"""

    # data used by the calculator
    _current_calc: list[_CalcStringBase] = []  # the current calculation
    _current_input: str = ""  # the current number input

    _user_variables: VariablesType = VariablesType({})  # user defined variables

    def __init__(
        self,
        update_display: Callable[[], None],
        clear_display: Callable[[], None],
        write_to_display: Callable[[str], None],
        bell: Callable[[], None],
        vars_popup: Callable[[], None],
        memval: StringVar,
    ) -> None:
        self.update_display = update_display
        self.clear_display = clear_display
        self.write_to_display = write_to_display
        self.bell = bell
        self.vars_popup = vars_popup
        self._memval = memval
