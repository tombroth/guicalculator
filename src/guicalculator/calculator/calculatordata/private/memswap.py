from ...logwrapper import object_wrapper
from ...numtostr import numtostr
from ..calculatordata import CalculatorData
from .getcurinpt import get_current_input
from .getmem import get_current_memory


@object_wrapper
def memory_swap(self: CalculatorData) -> None:
    """
    memory_swap - Swap the value stored in memory with the current number
    being input.

    Notes
    -----
    Cannot do a simple swap like (a,b) = (b,a) because we need to cal .set
    on the tk.StringVar that stores the memory value, and we round and
    format the display.

    As a side effect, will round the number currently being input to the
    precision in the Decimal context.
    """

    # get current value (formatted with commas)
    cur_num = numtostr(get_current_input(self), commas=True)

    # get current memory
    cur_mem = numtostr(get_current_memory(self))

    if cur_mem or cur_num:
        # store memory in current value
        self._current_input = cur_mem or ""

        # store retrieved current value in memory
        self._memval.set(cur_num or "")

        self.update_display()
    else:
        self.bell()
