"""test_update_current_calc.py - Test script for the update_current_calc function."""

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
from decimal import Decimal

from guicalculator.calculator.calculatordata.private.types import (
    _CalcStringFunction,
    _CalcStringNumber,
    _CalcStringString,
)
from guicalculator.calculator.calculatordata.private.updatecalc import update_current_calc
from guicalculator.globals import PI, CalculatorFunctions
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class UpdateCurrentCalcTest(SetupCalculatorDataTest):

    def test_update_current_calc(self):
        """Test the update_current_calc function."""

        """
        We have already validated (in test_validate_symbol_and_func) that all 
        the valid symbols and functions should be accepted, so this test just 
        checks that basic functionality is working.
        """
        test_data = [
            {
                "case": "No parameters",
                "current": {"calc": [], "inpt": "123"},
                "params": {},
                "ending": {"calc": [_CalcStringNumber(123)], "inpt": ""},
            },
            {
                "case": "123 **",
                "current": {"calc": [], "inpt": "123"},
                "params": {"symbol": "**"},
                "ending": {
                    "calc": [_CalcStringNumber(123), _CalcStringString("**")],
                    "inpt": "",
                },
            },
            {
                "case": "sqrt(123)",
                "current": {
                    "calc": [_CalcStringNumber(123), _CalcStringString("+")],
                    "inpt": "123",
                },
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "ending": {
                    "calc": [
                        _CalcStringNumber(123),
                        _CalcStringString("+"),
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Default variable e",
                "current": {"calc": [], "inpt": ""},
                "params": {"symbol": "e"},
                "ending": {"calc": [_CalcStringString("e")], "inpt": ""},
            },
            {
                "case": "Default variable PI",
                "current": {"calc": [], "inpt": ""},
                "params": {"symbol": PI},
                "ending": {"calc": [_CalcStringString(PI)], "inpt": ""},
            },
            {
                "case": "User variable x",
                "current": {
                    "calc": [],
                    "inpt": "",
                    "vars": {"x": Decimal("1234.56")},
                },
                "params": {"symbol": "x"},
                "ending": {
                    "calc": [_CalcStringString("x")],
                    "inpt": "",
                    "vars": {"x": Decimal("1234.56")},
                },
            },
            # Checks for adding multiplication symbol
            {
                "case": "Number input, no symbol, calc ends with number",
                "current": {
                    "calc": [_CalcStringNumber(123)],
                    "inpt": "123",
                },
                "params": {"symbol": ""},
                "ending": {
                    "calc": [
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input, no symbol, calc ends with variable",
                "current": {
                    "calc": [_CalcStringString("e")],
                    "inpt": "123",
                },
                "params": {"symbol": ""},
                "ending": {
                    "calc": [
                        _CalcStringString("e"),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input, no symbol, calc ends with close paren",
                "current": {
                    "calc": [_CalcStringString(")")],
                    "inpt": "123",
                },
                "params": {"symbol": ""},
                "ending": {
                    "calc": [
                        _CalcStringString(")"),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input, no symbol, calc ends with function",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "123",
                },
                "params": {"symbol": ""},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input, no symbol, calc ends with open paren",
                "current": {
                    "calc": [_CalcStringString("(")],
                    "inpt": "123",
                },
                "params": {"symbol": ""},
                "ending": {
                    "calc": [
                        _CalcStringString("("),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input, no symbol, calc ends with +",
                "current": {
                    "calc": [_CalcStringString("+")],
                    "inpt": "123",
                },
                "params": {"symbol": ""},
                "ending": {
                    "calc": [
                        _CalcStringString("+"),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and open parenthesis, calc ends with number",
                "current": {
                    "calc": [_CalcStringNumber(123)],
                    "inpt": "123",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and open parenthesis, calc ends with variable",
                "current": {
                    "calc": [_CalcStringString("e")],
                    "inpt": "123",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringString("e"),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and open parenthesis, calc ends with close paren",
                "current": {
                    "calc": [_CalcStringString(")")],
                    "inpt": "123",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringString(")"),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and open parenthesis, calc ends with function",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        )
                    ],
                    "inpt": "123",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and open parenthesis, calc ends with open paren",
                "current": {
                    "calc": [_CalcStringString("(")],
                    "inpt": "123",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringString("("),
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and open parenthesis, calc ends with +",
                "current": {
                    "calc": [_CalcStringString("+")],
                    "inpt": "123",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringString("+"),
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and +, calc ends with number",
                "current": {
                    "calc": [_CalcStringNumber(123)],
                    "inpt": "123",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and +, calc ends with variable",
                "current": {
                    "calc": [_CalcStringString("e")],
                    "inpt": "123",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringString("e"),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and +, calc ends with close paren",
                "current": {
                    "calc": [_CalcStringString(")")],
                    "inpt": "123",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringString(")"),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and +, calc ends with function",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        )
                    ],
                    "inpt": "123",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                        _CalcStringString("*"),
                        _CalcStringNumber(123),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and +, calc ends with open paren",
                "current": {
                    "calc": [_CalcStringString("(")],
                    "inpt": "123",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringString("("),
                        _CalcStringNumber(123),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Number input and +, calc ends with +",
                "current": {
                    "calc": [_CalcStringString("+")],
                    "inpt": "123",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringString("+"),
                        _CalcStringNumber(123),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Function input, calc ends with number",
                "current": {
                    "calc": [_CalcStringNumber(123)],
                    "inpt": "123",
                },
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "ending": {
                    "calc": [
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Function input, calc ends with variable",
                "current": {
                    "calc": [_CalcStringString("e")],
                    "inpt": "123",
                },
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "ending": {
                    "calc": [
                        _CalcStringString("e"),
                        _CalcStringString("*"),
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Function input, calc ends with close paren",
                "current": {
                    "calc": [_CalcStringString(")")],
                    "inpt": "123",
                },
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "ending": {
                    "calc": [
                        _CalcStringString(")"),
                        _CalcStringString("*"),
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Function input, calc ends with function",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        )
                    ],
                    "inpt": "123",
                },
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                        _CalcStringString("*"),
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Function input, calc ends with open paren",
                "current": {
                    "calc": [_CalcStringString("(")],
                    "inpt": "123",
                },
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "ending": {
                    "calc": [
                        _CalcStringString("("),
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Function input, calc ends with +",
                "current": {
                    "calc": [_CalcStringString("+")],
                    "inpt": "123",
                },
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "ending": {
                    "calc": [
                        _CalcStringString("+"),
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Variable input, no number, calc ends with number",
                "current": {
                    "calc": [_CalcStringNumber(123)],
                    "inpt": "",
                },
                "params": {"symbol": "e"},
                "ending": {
                    "calc": [
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringString("e"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Variable input, no number, calc ends with variable",
                "current": {
                    "calc": [_CalcStringString("e")],
                    "inpt": "",
                },
                "params": {"symbol": "e"},
                "ending": {
                    "calc": [
                        _CalcStringString("e"),
                        _CalcStringString("*"),
                        _CalcStringString("e"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Variable input, no number, calc ends with close paren",
                "current": {
                    "calc": [_CalcStringString(")")],
                    "inpt": "",
                },
                "params": {"symbol": "e"},
                "ending": {
                    "calc": [
                        _CalcStringString(")"),
                        _CalcStringString("*"),
                        _CalcStringString("e"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Variable input, no number, calc ends with function",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        )
                    ],
                    "inpt": "",
                },
                "params": {"symbol": "e"},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                        _CalcStringString("*"),
                        _CalcStringString("e"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Variable input, no number, calc ends with open paren",
                "current": {
                    "calc": [_CalcStringString("(")],
                    "inpt": "",
                },
                "params": {"symbol": "e"},
                "ending": {
                    "calc": [
                        _CalcStringString("("),
                        _CalcStringString("e"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Variable input, no number, calc ends with +",
                "current": {
                    "calc": [_CalcStringString("+")],
                    "inpt": "",
                },
                "params": {"symbol": "e"},
                "ending": {
                    "calc": [
                        _CalcStringString("+"),
                        _CalcStringString("e"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Open parenthesis input, no number, calc ends with number",
                "current": {
                    "calc": [_CalcStringNumber(123)],
                    "inpt": "",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringNumber(123),
                        _CalcStringString("*"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Open parenthesis input, no number, calc ends with variable",
                "current": {
                    "calc": [_CalcStringString("e")],
                    "inpt": "",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringString("e"),
                        _CalcStringString("*"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Open parenthesis input, no number, calc ends with close paren",
                "current": {
                    "calc": [_CalcStringString(")")],
                    "inpt": "",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringString(")"),
                        _CalcStringString("*"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Open parenthesis input, no number, calc ends with function",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        )
                    ],
                    "inpt": "",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                        _CalcStringString("*"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Open parenthesis input, no number, calc ends with open paren",
                "current": {
                    "calc": [_CalcStringString("(")],
                    "inpt": "",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringString("("),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Open parenthesis input, no number, calc ends with +",
                "current": {
                    "calc": [_CalcStringString("+")],
                    "inpt": "",
                },
                "params": {"symbol": "("},
                "ending": {
                    "calc": [
                        _CalcStringString("+"),
                        _CalcStringString("("),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Close parenthesis input, no number, calc ends with number",
                "current": {
                    "calc": [_CalcStringNumber(123)],
                    "inpt": "",
                },
                "params": {"symbol": ")"},
                "ending": {
                    "calc": [
                        _CalcStringNumber(123),
                        _CalcStringString(")"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Close parenthesis input, no number, calc ends with variable",
                "current": {
                    "calc": [_CalcStringString("e")],
                    "inpt": "",
                },
                "params": {"symbol": ")"},
                "ending": {
                    "calc": [
                        _CalcStringString("e"),
                        _CalcStringString(")"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Close parenthesis input, no number, calc ends with close paren",
                "current": {
                    "calc": [_CalcStringString(")")],
                    "inpt": "",
                },
                "params": {"symbol": ")"},
                "ending": {
                    "calc": [
                        _CalcStringString(")"),
                        _CalcStringString(")"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Close parenthesis input, no number, calc ends with function",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        )
                    ],
                    "inpt": "",
                },
                "params": {"symbol": ")"},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                        _CalcStringString(")"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Close parenthesis input, no number, calc ends with open paren",
                "current": {
                    "calc": [_CalcStringString("(")],
                    "inpt": "",
                },
                "params": {"symbol": ")"},
                "ending": {
                    "calc": [
                        _CalcStringString("("),
                        _CalcStringString(")"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "Close parenthesis input, no number, calc ends with +",
                "current": {
                    "calc": [_CalcStringString("+")],
                    "inpt": "",
                },
                "params": {"symbol": ")"},
                "ending": {
                    "calc": [
                        _CalcStringString("+"),
                        _CalcStringString(")"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "+ input, no number, calc ends with number",
                "current": {
                    "calc": [_CalcStringNumber(123)],
                    "inpt": "",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringNumber(123),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "+ input, no number, calc ends with variable",
                "current": {
                    "calc": [_CalcStringString("e")],
                    "inpt": "",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringString("e"),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "+ input, no number, calc ends with close paren",
                "current": {
                    "calc": [_CalcStringString(")")],
                    "inpt": "",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringString(")"),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "+ input, no number, calc ends with function",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        )
                    ],
                    "inpt": "",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "+ input, no number, calc ends with open paren",
                "current": {
                    "calc": [_CalcStringString("(")],
                    "inpt": "",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringString("("),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
            {
                "case": "+ input, no number, calc ends with +",
                "current": {
                    "calc": [_CalcStringString("+")],
                    "inpt": "",
                },
                "params": {"symbol": "+"},
                "ending": {
                    "calc": [
                        _CalcStringString("+"),
                        _CalcStringString("+"),
                    ],
                    "inpt": "",
                },
            },
        ]

        for data in test_data:
            with self.subTest(msg="update_current_calc: " + data["case"]):
                self.run_basic_test(
                    func=update_current_calc,
                    cur_vals=data["current"],
                    params={"self": self.calc_data, **data["params"]},
                    end_vals=data["ending"],
                )

    def test_update_current_calc_invalid_input(self):
        """Test the update_current_calc function with invlaid input"""

        """
        We have already validated (test_validate_symbol_and_func_invalid_input) 
        that all the invalid symbols and functions should be caught, so this test 
        just checks that basic functionality is working.
        """
        test_data = [
            {
                "case": "Both symbol and func specified",
                "current": {"calc": [], "inpt": "123"},
                "params": {
                    "symbol": "+",
                    "func": CalculatorFunctions.SQUAREROOT,
                },
                "result": ValueError,
            },
            {
                "case": "Unknown symbol",
                "current": {"calc": [], "inpt": "123", "vars": {}},
                "params": {
                    "symbol": "abcde",
                },
                "result": ValueError,
            },
            {
                "case": "Keyword",
                "current": {"calc": [], "inpt": "123"},
                "params": {
                    "symbol": "def",
                },
                "result": ValueError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="update_current_calc: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=update_current_calc,
                        cur_vals=data["current"],
                        params={"self": self.calc_data, **data["params"]},
                    )


if __name__ == "__main__":
    unittest.main()
