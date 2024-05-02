"""test_clear_all.py - Test script for the clear_all function."""

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

from guicalculator.calculator.calculatordata import _CalcStringNumber, _CalcStringString
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class ClearAllTest(SetupCalculatorDataTest):

    def test_clear_all(self):
        """Test the clear_all function."""

        test_data = [
            {
                "case": "Clear value, input exists",
                "current": {
                    "calc": [_CalcStringNumber(1), _CalcStringString("+")],
                    "inpt": "123",
                },
                "ending": {"calc": [], "inpt": ""},
            },
            {
                "case": "Clear value but no input",
                "current": {
                    "calc": [_CalcStringNumber(1), _CalcStringString("+")],
                    "inpt": "",
                },
                "ending": {"calc": [], "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="clear_all: " + data["case"]):
                # make sure clear_all calls clear_display
                cleardispcnt = self.clear_display.call_count

                self.run_basic_test(
                    func=self.calc_data.clear_all,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

                self.assertEqual((cleardispcnt + 1), self.clear_display.call_count)

    # clear_all doesn't take input, so there isn't an invalid input check


if __name__ == "__main__":
    unittest.main()
