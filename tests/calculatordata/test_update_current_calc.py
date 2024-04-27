import unittest
from decimal import Decimal

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
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {},
                "ending": {"disp": "123", "eval": "Decimal('123')", "inpt": ""},
            },
            {
                "case": "123 ** 2",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": "** 2"},
                "ending": {
                    "disp": "123 ** 2",
                    "eval": "Decimal('123') ** 2",
                    "inpt": "",
                },
            },
            {
                "case": "sqrt(123)",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "ending": {
                    "disp": "sqrt(123)",
                    "eval": "Decimal.sqrt(Decimal('123'))",
                    "inpt": "",
                },
            },
            {
                "case": "Inversion: (1/3)",
                "current": {"disp": "", "eval": "", "inpt": "3"},
                "params": {"func": CalculatorFunctions.INVERSION},
                "ending": {"disp": "(1/3)", "eval": "(1/Decimal('3'))", "inpt": ""},
            },
            {
                "case": "Default variable e",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "params": {"symbol": "e"},
                "ending": {"disp": "e", "eval": "e", "inpt": ""},
            },
            {
                "case": "Default variable PI",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "params": {"symbol": PI},
                "ending": {"disp": PI, "eval": PI, "inpt": ""},
            },
            {
                "case": "User variable x",
                "current": {
                    "disp": "",
                    "eval": "",
                    "inpt": "",
                    "vars": {"x": Decimal("1234.56")},
                },
                "params": {"symbol": "x"},
                "ending": {"disp": "x", "eval": "x", "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="update_current_calc: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.update_current_calc,
                    cur_vals=data["current"],
                    params=data["params"],
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
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {
                    "symbol": "+",
                    "func": CalculatorFunctions.INVERSION,
                },
                "result": ValueError,
            },
            {
                "case": "Unknown symbol",
                "current": {"disp": "", "eval": "", "inpt": "123", "vars": {}},
                "params": {
                    "symbol": "abcde",
                },
                "result": ValueError,
            },
            {
                "case": "Keyword",
                "current": {"disp": "", "eval": "", "inpt": "123"},
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
                        func=self.calc_data.update_current_calc,
                        cur_vals=data["current"],
                        params=data["params"],
                    )


if __name__ == "__main__":
    unittest.main()
