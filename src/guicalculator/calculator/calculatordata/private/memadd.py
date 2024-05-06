from decimal import Decimal

from ...logwrapper import object_wrapper
from ...numtostr import numtostr
from ..calculatordata import CalculatorData
from .getcurinpt import get_current_input
from .getmem import get_current_memory


@object_wrapper
def memory_add(self: CalculatorData, addto: bool = True) -> None:
    """
    memory_add - Add or subtract the current number being input to or from
    the value stored in memory.

    Notes
    -----
    If addto is passed in as false, will subtract the value being input
    from memory by multiplying the value by -1 before adding.

    Parameters
    ----------
    addto : bool, optional
        If true, performs addition. If false, performs subtraction.
        By default True.
    """

    # adding or subtracting
    if addto:
        sign = Decimal(1)
    else:
        sign = Decimal(-1)

    # get the current input number
    cur_val = get_current_input(self)
    if cur_val:

        # get current memory
        cur_mem = get_current_memory(self) or Decimal(0)

        # add (or subtract)
        mv = cur_mem + (cur_val * sign)
        self._memval.set(numtostr(mv, commas=True) or "")
    else:
        self.bell()
