"""
memstore.py - The memory_store function.
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
