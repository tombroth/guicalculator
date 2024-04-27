import unittest

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class ButtonPressTest(SetupCalculatorDataTest):

    def test_button_press(self):
        """Test the button_press function."""

        test_data = [
            {
                "case": "Button press 1",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": 1},
                "ending": {"disp": "", "eval": "", "inpt": "1231"},
            },
            {
                "case": "Button press +",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": "+"},
                "ending": {"disp": "123 +", "eval": "Decimal('123') +", "inpt": ""},
            },
            {
                "case": "Button press ** 2",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": "** 2"},
                "ending": {
                    "disp": "123 ** 2",
                    "eval": "Decimal('123') ** 2",
                    "inpt": "",
                },
            },
        ]

        for data in test_data:
            with self.subTest(msg="button_press: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.button_press,
                    cur_vals=data["current"],
                    params=data["params"],
                    end_vals=data["ending"],
                )

    def test_button_press_invalid_input(self):
        """Test the button_press function with invalid input."""

        test_data = [
            {
                "case": "Button press 1 as str",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": "1"},
                "result": ValueError,
            },
            {
                "case": "Invalid symbol",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": "+-*/"},
                "result": ValueError,
            },
            {
                "case": "No input",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": None},
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="button_press: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.button_press,
                        cur_vals=data["current"],
                        params=data["params"],
                    )


if __name__ == "__main__":
    unittest.main()
