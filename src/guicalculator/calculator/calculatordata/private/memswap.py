"""
memswap.py - The memory_swap function.
"""

"""
Copyright (c) 2024 Thomas Brotherton

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

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
