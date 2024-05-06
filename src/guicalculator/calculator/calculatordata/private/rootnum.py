"""
rootnum.py - The root_number function.
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

from ....globals import CalculatorFunctions
from ...logwrapper import logerror, object_wrapper
from ..calculatordata import CalculatorData
from .updatecalc import update_current_calc


@object_wrapper
def root_number(self: CalculatorData) -> None:
    """
    root_number - Convert the current number being input to its
    square root: Decimal.sqrt(x).

    Notes
    -----
    As a side effect, will round the number currently being input to the
    precision in the Decimal context.
    """

    try:
        update_current_calc(self, func=CalculatorFunctions.SQUAREROOT)
    except Exception as e:
        logerror(e, "root_number", 2)
        self.bell()
