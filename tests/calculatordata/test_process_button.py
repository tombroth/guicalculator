"""test_process_button.py - Test script for the process_button function."""

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

import unittest

from guicalculator.calculator.calculatordata.functions.processbutton import (
    process_button,
)
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class ProcessButtonTest(SetupCalculatorDataTest):

    # skipping valid test for now, it's just a big match/case statement to call
    # other functions and those functions are already tested
    #
    # the alternative would be to use MagicMock just to make sure the
    # specified input runs the specified function
    #
    # def test_process_button(self):
    #     pass

    def test_process_button_invalid_input(self):
        """Test the process_button function with invalid input."""

        """
        passing invalid buttontxt with the "button" command 
        get passed through process_button and button_press
        but get caught in update_current_calc when it 
        calls validate_symbol_and_func, and it raises an
        error. We already have tests to catch that
        condition in validate_symbol_and_func.
        """
        test_data = [
            {
                "case": "Unknown function Call",
                "current": {"calc": [], "inpt": ""},
                "params": {"buttoncmd": "UnknownFunctionCall"},
                "result": ValueError,
            },
            {
                "case": "Passing int instead of str",
                "current": {"calc": [], "inpt": ""},
                "params": {"buttoncmd": 123},
                "result": ValueError,
            },
            {
                "case": "Passing empty string",
                "current": {"calc": [], "inpt": ""},
                "params": {"buttoncmd": ""},
                "result": ValueError,
            },
            {
                "case": "Passing None",
                "current": {"calc": [], "inpt": ""},
                "params": {"buttoncmd": None},
                "result": ValueError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="process_button: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=process_button,
                        cur_vals=data["current"],
                        params={"self": self.calc_data, **data["params"]},
                    )


if __name__ == "__main__":
    unittest.main()
