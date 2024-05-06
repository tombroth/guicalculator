from ...logwrapper import object_wrapper
from ...numtostr import numtostr
from ..calculatordata import CalculatorData
from .getcurinpt import get_current_input


@object_wrapper
def memory_store(self: CalculatorData) -> None:
    """
    memory_store - Change the value stored in memory to be the same as the
    current number being input.

    Notes
    -----
    Cannot do a simple set because we round and format the display.
    """

    # get current value
    cur_val = get_current_input(self)

    if cur_val:
        # store it
        self._memval.set(numtostr(cur_val, commas=True) or "")
    else:
        self.bell()
