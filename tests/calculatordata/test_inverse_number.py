import unittest
from decimal import InvalidOperation

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class InverseNumberTest(SetupCalculatorDataTest):

    def test_inverse_number(self):
        """Test the inverse_number function."""

        test_data = [
            {
                "case": "2 as str",
                "current": {"disp": "", "eval": "", "inpt": "2"},
                "ending": {"disp": "(1/2)", "eval": "(1/Decimal('2'))", "inpt": ""},
            },
            {
                "case": "2 as int",
                "current": {"disp": "", "eval": "", "inpt": 2},
                "ending": {"disp": "(1/2)", "eval": "(1/Decimal('2'))", "inpt": ""},
            },
            {
                "case": "No input value",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "ending": {"disp": "", "eval": "", "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="inverse_number: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.inverse_number,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_inverse_number_invalid_input(self):
        """Test the inverse_number function with invalid input."""

        test_data = [
            {
                "case": "Text stored in input",
                "current": {"disp": "", "eval": "", "inpt": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "List stored in input",
                "current": {"disp": "", "eval": "", "inpt": ["1", "2", "3"]},
                "result": ValueError,
            },
            {
                "case": "Injection attack #1",
                "current": {
                    "disp": "",
                    "eval": "",
                    "inpt": "__import__('os').system('dir')",
                },
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack #2",
                "current": {
                    "disp": "",
                    "eval": "",
                    "inpt": lambda: __import__("os").system("dir"),
                },
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="inverse_number: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.inverse_number,
                        cur_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
