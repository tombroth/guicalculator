"""test_backspace.py - Test script for the backspace function."""

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

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class BackspaceTest(SetupCalculatorDataTest):

    def test_backspace(self):
        """Test the backspace function"""

        test_data = [
            {
                "case": "Backspace",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "ending": {"disp": "", "eval": "", "inpt": "12"},
            },
            {
                "case": "Backspace but no input",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "ending": {"disp": "", "eval": "", "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="button_press: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.backspace,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    # backspace doesn't take input, so there isn't an invalid input check


if __name__ == "__main__":
    unittest.main()
