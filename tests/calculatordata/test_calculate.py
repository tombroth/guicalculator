"""test_calculate.py - Test script for the calculate function."""

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

from guicalculator.calculator.calculatordata.private.types import (
    _CalcStringFunction,
    _CalcStringNumber,
    _CalcStringString,
)
from guicalculator.calculator.calculatordata.private.calculate import calculate
from guicalculator.globals.constants import PI
from guicalculator.globals.enums import CalculatorFunctions
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class CalculateTest(SetupCalculatorDataTest):

    def test_calculate(self):
        """Test the calculate function."""

        """
        We have already extensively tested the parser in test_supportfuncs.py
        so this test just checks that basic functionality is working. The
        calculate function should put the result from the parser into 
        the current_input (inpt) variable.
        """

        test_data = [
            {
                "case": "1 + 1",
                "current": {
                    "calc": [_CalcStringNumber(1), _CalcStringString("+")],
                    "inpt": "1",
                },
                "ending": {"calc": [], "inpt": "2"},
            },
            {
                "case": "2 ** 3",
                "current": {
                    "calc": [_CalcStringNumber(2), _CalcStringString("**")],
                    "inpt": "3",
                },
                "ending": {"calc": [], "inpt": "8"},
            },
            {
                "case": "No input value",
                "current": {"calc": [], "inpt": ""},
                "ending": {"calc": [], "inpt": ""},
            },
            {
                "case": "Default variable e",
                "current": {"calc": [_CalcStringString("e")], "inpt": ""},
                "ending": {"calc": [], "inpt": "2.718281828459045235360287471"},
            },
            {
                "case": "Default Variable PI",
                "current": {"calc": [_CalcStringString(PI)], "inpt": ""},
                "ending": {"calc": [], "inpt": "3.141592653589793238462643383"},
            },
            {
                "case": "User variable x",
                "current": {
                    "calc": [_CalcStringString("x")],
                    "inpt": "",
                    "vars": {"x": Decimal("1234.56")},
                },
                "ending": {"calc": [], "inpt": "1234.56"},
            },
            {
                "case": "Nested functions",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT,
                            _CalcStringFunction(
                                CalculatorFunctions.SQUAREROOT, _CalcStringNumber(81)
                            ),
                        )
                    ],
                    "inpt": "",
                    "vars": {},
                },
                "ending": {"calc": [], "inpt": "3"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="calculate: " + data["case"]):
                self.run_basic_test(
                    func=calculate,
                    cur_vals=data["current"],
                    params={"self": self.calc_data},
                    end_vals=data["ending"],
                )

    def test_calculate_invalid_input(self):
        """Test the calculate function with invalid data."""

        """
        We have already extensively tested the parser in test_supportfuncs.py
        so this test just checks that basic functionality is working. On error 
        the calculate function should clear the current_input (inpt), 
        current_display_calc (disp), and current_eval_calc (eval) variables
        and print an error message to stdout.
        """
        test_data = [
            {
                "case": "1 + 1",
                "current": {"calc": [_CalcStringString("Decimal(1)"), _CalcStringString("+")], "inpt": "1"},
                "ending": {"calc": [], "inpt": ""},
                "result": "Decimal function should only have str parameter",
            },
            {
                "case": "Code injection",
                "current": {
                    "calc": [_CalcStringString("__import__('os').system('dir')")],
                    "inpt": "",
                },
                "ending": {"calc": [], "inpt": ""},
                "result": "Unknown type of ast.Call",
            },
        ]

        for data in test_data:
            with self.subTest(msg="calculate: " + data["case"]):
                with self.assertLogs(level=logging.ERROR) as logmsgs:
                    self.run_basic_test(
                        func=calculate,
                        cur_vals=data["current"],
                        params={"self": self.calc_data},
                        end_vals=data["ending"],
                    )
                    self.assertTrue(
                        any(data["result"] in errmsg for errmsg in logmsgs.output)
                    )


if __name__ == "__main__":
    unittest.main()
