"""test_get_num_fnc_sym.py - Test script for the get_num_fnc_sym function."""

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

from decimal import Decimal
import unittest

from guicalculator.calculator.calculatordata.private.getnumfncsym import get_num_fnc_sym
from guicalculator.calculator.calculatordata.private.types import (
    _CalcStringFunction,
    _CalcStringNumber,
    _CalcStringString,
)
from guicalculator.globals.enums import CalculatorFunctions, CalculatorSymbols
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class GetNumFncSymTest(SetupCalculatorDataTest):

    def test_get_num_fnc_sym(self):
        """Test the get_num_fnc_sym function."""

        test_data = [
            {
                "case": "Both parameters empty",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
                "ending": {"calc": [], "inpt": ""},
                "result": (None, None, None),
            },
            {
                "case": "Both parameters empty #2",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": None,
                    "func": None,
                },
                "ending": {"calc": [], "inpt": ""},
                "result": (None, None, None),
            },
            {
                "case": "(",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": CalculatorSymbols.OPENPAREN,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
                "ending": {"calc": [], "inpt": ""},
                "result": (None, None, _CalcStringString(CalculatorSymbols.OPENPAREN)),
            },
            {
                "case": ")",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": CalculatorSymbols.CLOSEPAREN,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
                "ending": {"calc": [], "inpt": ""},
                "result": (None, None, _CalcStringString(CalculatorSymbols.CLOSEPAREN)),
            },
            {
                "case": "/",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": CalculatorSymbols.DIVISION,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
                "ending": {"calc": [], "inpt": ""},
                "result": (None, None, _CalcStringString(CalculatorSymbols.DIVISION)),
            },
            {
                "case": "*",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": CalculatorSymbols.MULTIPLICATION,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
                "ending": {"calc": [], "inpt": ""},
                "result": (
                    None,
                    None,
                    _CalcStringString(CalculatorSymbols.MULTIPLICATION),
                ),
            },
            {
                "case": "-",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": CalculatorSymbols.SUBTRACTION,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
                "ending": {"calc": [], "inpt": ""},
                "result": (
                    None,
                    None,
                    _CalcStringString(CalculatorSymbols.SUBTRACTION),
                ),
            },
            {
                "case": "+",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": CalculatorSymbols.ADDITION,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
                "ending": {"calc": [], "inpt": ""},
                "result": (None, None, _CalcStringString(CalculatorSymbols.ADDITION)),
            },
            {
                "case": "**",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": CalculatorSymbols.EXPONENTIATION,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
                "ending": {"calc": [], "inpt": ""},
                "result": (
                    None,
                    None,
                    _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                ),
            },
            {
                "case": "sqrt, number in input, remove_parameter True but ignored",
                "current": {
                    "calc": [
                        _CalcStringNumber(321),
                        _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "123",
                },
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.SQUAREROOT,
                    "remove_parameter": True,
                },
                "ending": {
                    "calc": [
                        _CalcStringNumber(321),
                        _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "123",
                },
                "result": (
                    None,
                    _CalcStringFunction(
                        CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                    ),
                    None,
                ),
            },
            {
                "case": "sqrt, empty input, number at end of calc, remove_parameter False",
                "current": {
                    "calc": [
                        _CalcStringNumber(321),
                        _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "",
                },
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.SQUAREROOT,
                },
                "ending": {
                    "calc": [
                        _CalcStringNumber(321),
                        _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "",
                },
                "result": (
                    None,
                    _CalcStringFunction(
                        CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                    ),
                    None,
                ),
            },
            {
                "case": "sqrt, empty input, number at end of calc, remove_parameter True",
                "current": {
                    "calc": [
                        _CalcStringNumber(321),
                        _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                        _CalcStringNumber(123),
                    ],
                    "inpt": "",
                },
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.SQUAREROOT,
                    "remove_parameter": True,
                },
                "ending": {
                    "calc": [
                        _CalcStringNumber(321),
                        _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                    ],
                    "inpt": "",
                },
                "result": (
                    None,
                    _CalcStringFunction(
                        CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                    ),
                    None,
                ),
            },
            {
                "case": "sqrt, empty input, function at end of calc, remove_parameter False",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "",
                },
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.SQUAREROOT,
                },
                "ending": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "",
                },
                "result": (
                    None,
                    _CalcStringFunction(
                        CalculatorFunctions.SQUAREROOT,
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ),
                    None,
                ),
            },
            {
                "case": "sqrt, empty input, function at end of calc, remove_parameter True",
                "current": {
                    "calc": [
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ],
                    "inpt": "",
                },
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.SQUAREROOT,
                    "remove_parameter": True,
                },
                "ending": {
                    "calc": [],
                    "inpt": "",
                },
                "result": (
                    None,
                    _CalcStringFunction(
                        CalculatorFunctions.SQUAREROOT,
                        _CalcStringFunction(
                            CalculatorFunctions.SQUAREROOT, _CalcStringNumber(123)
                        ),
                    ),
                    None,
                ),
            },
            {
                "case": "sqrt, empty input, variable at end of calc, remove_parameter False",
                "current": {
                    "calc": [
                        _CalcStringNumber(321),
                        _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                        _CalcStringString("x"),
                    ],
                    "inpt": "",
                    "vars": {"x": Decimal(123)},
                },
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.SQUAREROOT,
                },
                "ending": {
                    "calc": [
                        _CalcStringNumber(321),
                        _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                        _CalcStringString("x"),
                    ],
                    "inpt": "",
                    "vars": {"x": Decimal(123)},
                },
                "result": (
                    None,
                    _CalcStringFunction(
                        CalculatorFunctions.SQUAREROOT, _CalcStringString("x")
                    ),
                    None,
                ),
            },
            {
                "case": "sqrt, empty input, variable at end of calc, remove_parameter True",
                "current": {
                    "calc": [
                        _CalcStringNumber(321),
                        _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                        _CalcStringString("x"),
                    ],
                    "inpt": "",
                    "vars": {"x": Decimal(123)},
                },
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.SQUAREROOT,
                    "remove_parameter": True,
                },
                "ending": {
                    "calc": [
                        _CalcStringNumber(321),
                        _CalcStringString(CalculatorSymbols.EXPONENTIATION),
                    ],
                    "inpt": "",
                    "vars": {"x": Decimal(123)},
                },
                "result": (
                    None,
                    _CalcStringFunction(
                        CalculatorFunctions.SQUAREROOT, _CalcStringString("x")
                    ),
                    None,
                ),
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_num_fnc_sym: " + data["case"]):
                res = self.run_basic_test(
                    func=get_num_fnc_sym,
                    cur_vals=data["current"],
                    params={"self": self.calc_data, **data["params"]},
                    end_vals=data["ending"],
                )
                self.assertEqual(res, data["result"])

    def test_get_num_fnc_sym_invalid_input(self):
        """Test the get_num_fnc_sym function with invalid data."""

        test_data = [
            {
                "case": "Invalid symbol parameter",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": ["a", "b"],
                    "func": CalculatorFunctions.NOFUNCTION,
                    "remove_parameter": False,
                },
                "result": TypeError,
            },
            {
                "case": "Invalid func parameter",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": {"a", "b", "c"},
                    "remove_parameter": False,
                },
                "result": TypeError,
            },
            # invalid remove_parameter is difficult to test because Python will cast to bool for us
            {
                "case": "No argument for function",
                "current": {"calc": [], "inpt": ""},
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.SQUAREROOT,
                    "remove_parameter": None,
                },
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_num_fnc_sym: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=get_num_fnc_sym,
                        cur_vals=data["current"],
                        params={"self": self.calc_data, **data["params"]},
                    )


if __name__ == "__main__":
    unittest.main()
