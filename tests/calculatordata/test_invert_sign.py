"""test_invert_sign.py - Test script for the invert_sign function."""

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
from decimal import InvalidOperation

from guicalculator.calculator.calculatordata import (
    _CalcStringFunction,
    _CalcStringNumber,
    _CalcStringString,
)
from guicalculator.globals.enums import CalculatorFunctions
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class InvertSignTest(SetupCalculatorDataTest):

    def test_invert_sign(self):
        """Test the invert_sign function."""

        test_data = [
            {
                "case": "123 as str",
                "current": {"inpt": "123"},
                "ending": {"inpt": "-123"},
            },
            {
                "case": "123 as int",
                "current": {"inpt": 123},
                "ending": {"inpt": "-123"},
            },
            {
                "case": "Variable",
                "current": {"calc": [_CalcStringString("e")], "inpt": ""},
                "ending": {
                    "calc": [
                        _CalcStringString("-"),
                        _CalcStringString("e"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Function",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(2)
                        )
                    ],
                    "inpt": "",
                },
                "ending": {
                    "calc": [
                        _CalcStringString("-"),
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(2)
                        ),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number in calc, empty input",
                "current": {"calc": [_CalcStringNumber(2)], "inpt": ""},
                "ending": {
                    "calc": [
                        _CalcStringString("-"),
                        _CalcStringNumber(2),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "double negative",
                "current": {
                    "calc": [
                        _CalcStringString("-"),
                        _CalcStringNumber(2),
                    ],
                    "inpt": "",
                },
                "ending": {
                    "calc": [
                        _CalcStringString("-"),
                        _CalcStringString("-"),
                        _CalcStringNumber(2),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Calc ends in string that is not a variable",
                "current": {"calc": [_CalcStringString("+")], "inpt": ""},
                "ending": {"calc": [_CalcStringString("+")], "inpt": ""},
            },
            {
                "case": "No input value",
                "current": {"inpt": ""},
                "ending": {"inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="invert_sign: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.invert_sign,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_invert_sign_invalid_input(self):
        """Test the invert_sign function with invalid input."""

        test_data = [
            {
                "case": "Text stored in input",
                "current": {"inpt": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "List stored in input",
                "current": {"inpt": ["1", "2", "3"]},
                "result": ValueError,
            },
            {
                "case": "Injection attack #1",
                "current": {"inpt": "__import__('os').system('dir')"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack #2",
                "current": {"inpt": lambda: __import__("os").system("dir")},
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="invert_sign: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.invert_sign,
                        cur_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
