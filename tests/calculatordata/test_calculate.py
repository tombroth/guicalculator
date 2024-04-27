from decimal import Decimal
from io import StringIO
import unittest
from unittest.mock import patch

from guicalculator.globals.constants import PI
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
                "current": {"disp": "1 +", "eval": "Decimal('1') +", "inpt": "1"},
                "ending": {"disp": "", "eval": "", "inpt": "2"},
            },
            {
                "case": "2 ** 3",
                "current": {"disp": "2 **", "eval": "Decimal('2') **", "inpt": "3"},
                "ending": {"disp": "", "eval": "", "inpt": "8"},
            },
            {
                "case": "No input value",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "ending": {"disp": "", "eval": "", "inpt": ""},
            },
            {
                "case": "Default variable e",
                "current": {"disp": "e", "eval": "e", "inpt": ""},
                "ending": {
                    "disp": "",
                    "eval": "",
                    "inpt": "2.718281828459045235360287471",
                },
            },
            {
                "case": "Default Variable PI",
                "current": {"disp": PI, "eval": PI, "inpt": ""},
                "ending": {
                    "disp": "",
                    "eval": "",
                    "inpt": "3.141592653589793238462643383",
                },
            },
            {
                "case": "User variable x",
                "current": {
                    "disp": "x",
                    "eval": "x",
                    "inpt": "",
                    "vars": {"x": Decimal("1234.56")},
                },
                "ending": {"disp": "", "eval": "", "inpt": "1234.56"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="calculate: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.calculate,
                    cur_vals=data["current"],
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
                "current": {"disp": "1 +", "eval": "Decimal(1) +", "inpt": "1"},
                "ending": {"disp": "", "eval": "", "inpt": ""},
                "result": "ERROR: Decimal function should only have str parameter",
            },
            {
                "case": "Code injection",
                "current": {
                    "disp": "",
                    "eval": "__import__('os').system('dir')",
                    "inpt": "",
                },
                "ending": {"disp": "", "eval": "", "inpt": ""},
                "result": "ERROR: Unknown type of ast.Call",
            },
        ]

        for data in test_data:
            with self.subTest(msg="calculate: " + data["case"]):
                with patch("sys.stdout", new=StringIO()) as fake_out:
                    self.run_basic_test(
                        func=self.calc_data.calculate,
                        cur_vals=data["current"],
                        end_vals=data["ending"],
                    )
                    # assertStartsWith would be nice
                    self.assertEqual(
                        fake_out.getvalue()[: len(data["result"])], data["result"]
                    )


if __name__ == "__main__":
    unittest.main()
