"""
memadd.py - The memory_add function.
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
