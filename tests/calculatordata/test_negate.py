"""test_negte.py - Test script for the negate function."""

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

from guicalculator.calculator.calculatordata.private.negate import negate
from guicalculator.calculator.calculatordata.private.types import (
    _CalcStringFunction,
    _CalcStringNumber,
    _CalcStringString,
)
from guicalculator.globals.enums import CalculatorFunctions
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class InvertSignTest(SetupCalculatorDataTest):

    def test_negate(self):
        """Test the negate function."""

        test_data = [
            {
                "case": "123 as str",
                "current": {"calc": [], "inpt": "123"},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.NEGATION, _CalcStringNumber(123)
                        )
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "123 as int",
                "current": {"calc": [], "inpt": 123},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.NEGATION, _CalcStringNumber(123)
                        )
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Variable",
                "current": {"calc": [_CalcStringString("e")], "inpt": ""},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.NEGATION, _CalcStringString("e")
                        )
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
                        _CalcStringFunction(
                            CalculatorFunctions.NEGATION,
                            _CalcStringFunction(
                                CalculatorFunctions.SQUAREROOT, _CalcStringNumber(2)
                            ),
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
                        _CalcStringFunction(
                            CalculatorFunctions.NEGATION, _CalcStringNumber(2)
                        )
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "double negative",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.NEGATION, _CalcStringNumber(2)
                        )
                    ],
                    "inpt": "",
                },
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.NEGATION,
                            _CalcStringFunction(
                                CalculatorFunctions.NEGATION, _CalcStringNumber(2)
                            ),
                        )
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
            with self.subTest(msg="negate: " + data["case"]):
                self.run_basic_test(
                    func=negate,
                    cur_vals=data["current"],
                    params={"self": self.calc_data},
                    end_vals=data["ending"],
                )

    def test_negate_invalid_input(self):
        """Test the negate function with invalid input."""

        lambdafunc = lambda: __import__("os").system("dir")

        test_data = [
            {
                "case": "Text stored in input",
                "current": {"inpt": "abcdefg"},
                "ending": {"inpt": "abcdefg"},
                "result": "InvalidOperation",
            },
            {
                "case": "List stored in input",
                "current": {"inpt": ["1", "2", "3"]},
                "ending": {"inpt": ["1", "2", "3"]},
                "result": "sign must be an integer with the value 0 or 1",
            },
            {
                "case": "Injection attack #1",
                "current": {"inpt": "__import__('os').system('dir')"},
                "ending": {"inpt": "__import__('os').system('dir')"},
                "result": "InvalidOperation",
            },
            {
                "case": "Injection attack #2",
                "current": {"inpt": lambdafunc},
                "ending": {"inpt": lambdafunc},
                "result": "conversion from function to Decimal is not supported",
            },
        ]

        for data in test_data:
            with self.subTest(msg="negate: " + data["case"]):
                with self.assertLogs(level=logging.ERROR) as logmsgs:
                    self.run_basic_test(
                        func=negate,
                        cur_vals=data["current"],
                        params={"self": self.calc_data},
                        end_vals=data["ending"],
                    )
                    self.assertTrue(
                        any(data["result"] in errmsg for errmsg in logmsgs.output)
                    )


if __name__ == "__main__":
    unittest.main()
