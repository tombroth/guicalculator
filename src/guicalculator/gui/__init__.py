"""guicalculator/gui - This is the directory with all the tkinter widgets for the calculator

Notes
-----
The file listing here is hierarchical. Any parent file can directly reference descendants, 
but any descendant referencing a parent would create a circular import error. Instead, 
descendants reference parents by functions passed in as parameters.

The files in this directory:

    guicalculator.py - This is the root Tk window. It contains:

        calcstyle.py - The calculator ttk.Style object

        calcfrm.py - The calculator top level frame. It contains:

            memdispfrm.py - The memory display frame.

            btndispfrm.py - The top level calculator button display frame. 

            varspopup.py - The variable selector popup window (called from the vars... button). It contains:

                varspopuptreefrm.py - The variable selector frame.

                varspopuptreefrmbuttons.py - The frame with buttons for the variable selector popup. It contains:

                    uservarseditpopup.py - The user variables editor popup (called from the edit button). It contains:

                        uservarseditfrm.py - The user variables editor popup top level frame.
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

from .guicalculator import GuiCalculator

__all__ = ["GuiCalculator"]
