"""test_root_number.py - Test script for the root_number function."""

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

import logging
import unittest
from decimal import Decimal

from guicalculator.calculator.calculatordata.private.rootnum import root_number
from guicalculator.calculator.calculatordata.private.types import (
    _CalcStringFunction,
    _CalcStringNumber,
    _CalcStringString,
)
from guicalculator.globals.enums import CalculatorFunctions
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class RootNumberTest(SetupCalculatorDataTest):

    def test_root_number(self):
        """Test the root_number function."""

        test_data = [
            {
                "case": "2 as str",
                "current": {"calc": [], "inpt": "2"},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(2)
                        )
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "2 as int",
                "current": {"calc": [], "inpt": 2},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(2)
                        )
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Apply to variable (no input, last element in calc is a default variable)",
                "current": {"calc": [_CalcStringString("e")], "inpt": ""},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringString("e")
                        )
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Apply to variable (no input, last element in calc is a user variable)",
                "current": {
                    "calc": [_CalcStringString("x")],
                    "inpt": "",
                    "vars": {"x": Decimal("1234.56")},
                },
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringString("x")
                        )
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Apply to variable (no input, last element in calc is a function)",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringString("x")
                        )
                    ],
                    "inpt": "",
                    "vars": {},
                },
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT,
                            _CalcStringFunction(
                                CalculatorFunctions.SQUAREROOT, _CalcStringString("x")
                            ),
                        )
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "No input, last element of calc is number",
                "current": {
                    "calc": [_CalcStringNumber(2)],
                    "inpt": "",
                },
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(2)
                        )
                    ],
                    "inpt": "",
                },
            },
        ]

        for data in test_data:
            with self.subTest(msg="root_number: " + data["case"]):
                self.run_basic_test(
                    func=root_number,
                    cur_vals=data["current"],
                    params={"self": self.calc_data},
                    end_vals=data["ending"],
                )

    def test_root_number_invalid_input(self):
        """Test the root_number function with invalid input."""

        lambdafunc = lambda: __import__("os").system("dir")

        test_data = [
            {
                "case": "No input value",
                "current": {"calc": [], "inpt": ""},
                "ending": {"calc": [], "inpt": ""},
                "result": "No argument for function",
            },
            {
                "case": "No input, last element of calc not a variable or function",
                "current": {
                    "calc": [_CalcStringNumber(1), _CalcStringString("+")],
                    "inpt": "",
                },
                "ending": {
                    "calc": [_CalcStringNumber(1), _CalcStringString("+")],
                    "inpt": "",
                },
                "result": "No argument for function",
            },
            {
                "case": "Text stored in input",
                "current": {"calc": [], "inpt": "abcdefg"},
                "ending": {"calc": [], "inpt": "abcdefg"},
                "result": "InvalidOperation",
            },
            {
                "case": "List stored in input",
                "current": {"calc": [], "inpt": ["1", "2", "3"]},
                "ending": {"calc": [], "inpt": ["1", "2", "3"]},
                "result": "sign must be an integer with the value 0 or 1",
            },
            {
                "case": "Injection attack #1",
                "current": {
                    "calc": [],
                    "inpt": "__import__('os').system('dir')",
                },
                "ending": {
                    "calc": [],
                    "inpt": "__import__('os').system('dir')",
                },
                "result": "InvalidOperation",
            },
            {
                "case": "Injection attack #2",
                "current": {
                    "calc": [],
                    "inpt": lambdafunc,
                },
                "ending": {
                    "calc": [],
                    "inpt": lambdafunc,
                },
                "result": "conversion from function to Decimal is not supported",
            },
        ]

        for data in test_data:
            with self.subTest(msg="root_number: " + data["case"]):
                with self.assertLogs(level=logging.ERROR) as logmsgs:
                    self.run_basic_test(
                        func=root_number,
                        cur_vals=data["current"],
                        params={"self": self.calc_data},
                        end_vals=data["ending"],
                    )
                    self.assertTrue(
                        any(data["result"] in errmsg for errmsg in logmsgs.output)
                    )


if __name__ == "__main__":
    unittest.main()
