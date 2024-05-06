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

from guicalculator.calculator.calculatordata.private.backspace import backspace
from guicalculator.calculator.calculatordata.private.types import (
    _CalcStringFunction,
    _CalcStringNumber,
    _CalcStringString,
)
from guicalculator.globals.enums import CalculatorFunctions
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class BackspaceTest(SetupCalculatorDataTest):

    def test_backspace(self):
        """Test the backspace function"""

        test_data = [
            {
                "case": "Backspace, number in input",
                "current": {"calc": [], "inpt": "123"},
                "ending": {"calc": [], "inpt": "12"},
            },
            {
                "case": "Backspace, no input, plain function in calculation",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        )
                    ],
                    "inpt": "",
                },
                "ending": {"calc": [], "inpt": "123"},
            },
            {
                "case": "Backspace, no input, plain function in calculation",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringString("e")
                        )
                    ],
                    "inpt": "",
                },
                "ending": {"calc": [_CalcStringString("e")], "inpt": ""},
            },
            {
                "case": "Backspace, no input, nested function in calculation",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT,
                            _CalcStringFunction(
                                CalculatorFunctions.SQUAREROOT, _CalcStringString("e")
                            ),
                        ),
                    ],
                    "inpt": "",
                },
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
                "case": "Backspace, no input, variable in calculation",
                "current": {
                    "calc": [
                        _CalcStringNumber(123),
                        _CalcStringString("**"),
                        _CalcStringString("e"),
                    ],
                    "inpt": "",
                },
                "ending": {
                    "calc": [_CalcStringNumber(123), _CalcStringString("**")],
                    "inpt": "",
                },
            },
            {
                "case": "Backspace, no input, operator in calculation",
                "current": {
                    "calc": [_CalcStringNumber(123), _CalcStringString("**")],
                    "inpt": "",
                },
                "ending": {
                    "calc": [
                        _CalcStringNumber(123),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Backspace, no input, number in calculation",
                "current": {"calc": [_CalcStringNumber(123)], "inpt": ""},
                "ending": {"calc": [], "inpt": "12"},
            },
            {
                "case": "Backspace but no input or calc",
                "current": {"calc": [], "inpt": ""},
                "ending": {"calc": [], "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="button_press: " + data["case"]):
                self.run_basic_test(
                    func=backspace,
                    cur_vals=data["current"],
                    params={"self": self.calc_data},
                    end_vals=data["ending"],
                )

    # backspace doesn't take input, so there isn't an invalid input check


if __name__ == "__main__":
    unittest.main()
