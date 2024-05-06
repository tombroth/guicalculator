from ...logwrapper import object_wrapper
from ...numtostr import numtostr
from ..calculatordata import CalculatorData
from .getmem import get_current_memory


@object_wrapper
def memory_recall(self: CalculatorData) -> None:
    """
    memory_recall - Replace the current number being input with the value
    stored in memory.
    """

    cur_mem = numtostr(get_current_memory(self))
    if cur_mem:
        self._current_input = cur_mem
        self.update_display()
    else:
        self.bell()
