import unittest
from decimal import InvalidOperation

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class InvertSignTest(SetupCalculatorDataTest):

    def test_invert_sign(self):
        """Test the invert_sign function."""

        test_data = [
            {
                "case": "123 as str",
                "current": {"inpt": "123"},
                "ending": {"inpt": "-123"},
            },
            {
                "case": "123 as int",
                "current": {"inpt": 123},
                "ending": {"inpt": "-123"},
            },
            {
                "case": "No input value",
                "current": {"inpt": ""},
                "ending": {"inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="invert_sign: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.invert_sign,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_invert_sign_invalid_input(self):
        """Test the invert_sign function with invalid input."""

        test_data = [
            {
                "case": "Text stored in input",
                "current": {"inpt": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "List stored in input",
                "current": {"inpt": ["1", "2", "3"]},
                "result": ValueError,
            },
            {
                "case": "Injection attack #1",
                "current": {"inpt": "__import__('os').system('dir')"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack #2",
                "current": {"inpt": lambda: __import__("os").system("dir")},
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="invert_sign: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.invert_sign,
                        cur_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
