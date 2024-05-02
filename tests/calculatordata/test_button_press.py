"""test_button_press.py - Test script for the button_press function."""

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


class ButtonPressTest(SetupCalculatorDataTest):

    def test_button_press(self):
        """Test the button_press function."""

        test_data = [
            {
                "case": "Button press 1",
                "current": {"calc": [], "inpt": "123"},
                "params": {"symbol": 1},
                "ending": {"calc": [], "inpt": "1231"},
            },
            {
                "case": "Button press +",
                "current": {"calc": [], "inpt": "123"},
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [_CalcStringNumber(123), _CalcStringString("+")],
                    "inpt": "",
                },
            },
            {
                "case": "Button press **",
                "current": {"calc": [], "inpt": "123"},
                "params": {"symbol": "**"},
                "ending": {
                    "calc": [_CalcStringNumber(123), _CalcStringString("**")],
                    "inpt": "",
                },
            },
            {
                "case": "No input",
                "current": {"calc": [], "inpt": "123"},
                "params": {"symbol": None},
                "ending": {
                    "calc": [_CalcStringNumber(123)],
                    "inpt": "",
                },
            },
        ]

        for data in test_data:
            with self.subTest(msg="button_press: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.button_press,
                    cur_vals=data["current"],
                    params=data["params"],
                    end_vals=data["ending"],
                )

    def test_button_press_invalid_input(self):
        """Test the button_press function with invalid input."""

        test_data = [
            {
                "case": "Button press 1 as str",
                "current": {"calc": [], "inpt": "123"},
                "params": {"symbol": "1"},
                "result": ValueError,
            },
            {
                "case": "Invalid symbol",
                "current": {"calc": [], "inpt": "123"},
                "params": {"symbol": "+-*/"},
                "result": ValueError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="button_press: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.button_press,
                        cur_vals=data["current"],
                        params=data["params"],
                    )


if __name__ == "__main__":
    unittest.main()
