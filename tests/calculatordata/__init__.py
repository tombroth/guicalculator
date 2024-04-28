"""tests/calculatordata - Tests for the CalculatorData object of guicalculator

The files in this directory:

    py.typed - type hints for mypy

    test__setup_calculatordata.py - The base class for CalculatorData tests

    test_*.py - Tests for individual functions with CalculatorData


Notes
-----
The test__setup_calculatordata.py file contains the base class SetupCalculatorDataTest 
for all the CalculatorData tests. This class doesn't perform any tests directly,
but it does define a unittest.TestCase object that has a CalculatorData object
with mocked functions to represent the callbacks to the GUI.

The main function in this class is run_basic_test, which runs a basic test. It
calls set_current_disp_eval_inpt to setup the CalculatorData environment, 
grabs the return value (if any) from the tested function, and then calls
chk_current_disp_eval_inpt to run basic assertions against the
CalculatorData environment. 

See test__setup_calculatordata.py for more details or any individual test
for examples on how to use this.

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
