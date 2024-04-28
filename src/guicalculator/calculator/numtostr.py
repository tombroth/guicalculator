"""
numtostr.py - Convert number to string.
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


def numtostr(
    val: int | float | Decimal,
    commas: bool = False,
    removeZeroes: bool = True,
) -> str:
    """
    numtostr - Convert number to string.

    Converts an int or float or Decimal to a string representation. Can
    add thousand separators and/or remove trailing zeroes after a decimal
    point.

    Notes
    -----
    As a side effect, will round the number currently being input to the
    precision in the Decimal context if removeZeroes is True.

    Parameters
    ----------
    val : int | float | Decimal
        Number to be converted
    commas : bool, optional
        True means add thosands separators (commas). By default False.
    removeZeroes : bool, optional
        True means remove trailing zeroes after the decimal point.
        By default True.

    Returns
    -------
    str
        The string representation of the number
    """

    v: int | float | Decimal
    if commas:
        c = ","
    else:
        c = ""

    if isinstance(val, Decimal):
        if val == val.to_integral_value() and removeZeroes:
            v = val.to_integral_value()
        else:
            if removeZeroes:
                v = (
                    val.quantize(Decimal(1))
                    if val == val.to_integral()
                    else val.normalize()
                )
            else:
                v = val
        fmt = "{0:" + c + "f}"
    elif val == int(val) and removeZeroes:
        v = int(val)
        fmt = "{0:" + c + "d}"
    else:
        v = val
        fmt = "{0:" + c + ".28g}"

    return fmt.format(v)
