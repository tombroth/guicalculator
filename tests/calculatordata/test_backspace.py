import unittest

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class BackspaceTest(SetupCalculatorDataTest):

    def test_backspace(self):
        """Test the backspace function"""

        test_data = [
            {
                "case": "Backspace",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "ending": {"disp": "", "eval": "", "inpt": "12"},
            },
            {
                "case": "Backspace but no input",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "ending": {"disp": "", "eval": "", "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="button_press: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.backspace,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    # backspace doesn't take input, so there isn't an invalid input check


if __name__ == "__main__":
    unittest.main()
