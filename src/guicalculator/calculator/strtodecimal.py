"""
strtodecimal.py - Convert string value to Decimal.
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

from .logwrapper import plain_wrapper


@plain_wrapper
def strtodecimal(val: str | None) -> Decimal | None:
    """
    strtodecimal  - convert string value to Decimal.

    Parameters
    ----------
    val : str | None
        Value to be converted, or None

    Returns
    -------
    Decimal | None
        Converted value, None if None was input
    """

    if val:
        # the + forces rounding to Decimal context
        return +Decimal(val.replace(",", ""))
    else:
        return None
