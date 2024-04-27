import unittest

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class ClearValueTest(SetupCalculatorDataTest):

    def test_clear_value(self):
        """Test the clear_value function."""

        test_data = [
            {
                "case": "Clear value, input exists",
                "current": {"disp": "1 +", "eval": "Decimal(1) +", "inpt": "123"},
                "ending": {"disp": "1 +", "eval": "Decimal(1) +", "inpt": ""},
            },
            {
                "case": "Clear value but no input",
                "current": {"disp": "1 +", "eval": "Decimal(1) +", "inpt": ""},
                "ending": {"disp": "", "eval": "", "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="clear_value: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.clear_value,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    # clear_value doesn't take input, so there isn't an invalid input check


if __name__ == "__main__":
    unittest.main()
