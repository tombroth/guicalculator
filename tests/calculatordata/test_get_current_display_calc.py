import unittest

from guicalculator.globals import CalculatorFunctions
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class GetCurrentDisplayCalcTest(SetupCalculatorDataTest):

    def test_get_current_display_calc(self):
        """Test the get_current_display_calc function."""

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
                "result": "123",
            },
            {
                "case": "123 +",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": "+"},
                "result": "123 +",
            },
            {
                "case": "sqrt(123)",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "result": "sqrt(123)",
            },
            {
                "case": "Inversion: (1/3)",
                "current": {"disp": "", "eval": "", "inpt": "3"},
                "params": {"func": CalculatorFunctions.INVERSION},
                "result": "(1/3)",
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_display_calc: " + data["case"]):
                res = self.run_basic_test(
                    func=self.calc_data.get_current_display_calc,
                    cur_vals=data["current"],
                    params=data["params"],
                    end_vals=data["current"],
                )
                self.assertEqual(res, data["result"])

    def test_get_current_display_calc_invalid_input(self):
        """Test the get_current_display_calc function with invalid input."""

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
        ]

        for data in test_data:
            with self.subTest(msg="get_current_display_calc: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.get_current_display_calc,
                        cur_vals=data["current"],
                        params=data["params"],
                    )


if __name__ == "__main__":
    unittest.main()
