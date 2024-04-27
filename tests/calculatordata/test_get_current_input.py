import unittest
from decimal import Decimal, InvalidOperation

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class GetCurrentInputTest(SetupCalculatorDataTest):

    def test_get_current_input(self):
        """Test the get_current_input function."""

        test_data = [
            {
                "case": "123 as str",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "result": Decimal("123"),
            },
            {
                "case": "123 as int",
                "current": {"disp": "", "eval": "", "inpt": 123},
                "result": Decimal("123"),
            },
            {
                "case": "No input value",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "result": Decimal("0"),
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_input: " + data["case"]):
                res = self.run_basic_test(
                    func=self.calc_data.get_current_input,
                    cur_vals=data["current"],
                    end_vals=data["current"],
                )
                self.assertEqual(res, data["result"])

    def test_get_current_input_invalid_input(self):
        """Test the get_current_input function with invalid input."""

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
            with self.subTest(msg="get_current_input: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.get_current_input,
                        cur_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
