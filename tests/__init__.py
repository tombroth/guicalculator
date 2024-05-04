"""tests - Tests for guicalculator

The files in this directory:

    py.typed - type hints for mypy

    test_evaluate_calculation.py - tests for the evaluate_calculation.py module

    test_logwrapper.py - test for the logwrapper.py module
    
    test_numtostr.py - tests for the numtostr.py module
    
    test_strtodecimal.py - tests for the strtodecimal.py module
    
    test_validate_user_var.py - tests for the validate_user_var.py module

The subdirectories in this directory:

    calculatordata - The tests for the calculatordata.py module

Notes
-----
Tests currently only exist for the modules within src/calculator. 

The modules within src/globals mostly declare things, so they are not tested.

The modules within src/gui are for the user interface, and I am not sure if
unit testing those would be possible or useful, they are best tested by using
the app.

The calculatordata.py module is large enough that it was split into one test per
function and grouped into a subdirectory.
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
