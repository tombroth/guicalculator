import unittest

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class ClearAllTest(SetupCalculatorDataTest):

    def test_clear_all(self):
        """Test the clear_all function."""

        test_data = [
            {
                "case": "Clear value, input exists",
                "current": {"disp": "1 +", "eval": "Decimal(1) +", "inpt": "123"},
                "ending": {"disp": "", "eval": "", "inpt": ""},
            },
            {
                "case": "Clear value but no input",
                "current": {"disp": "1 +", "eval": "Decimal(1) +", "inpt": ""},
                "ending": {"disp": "", "eval": "", "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="clear_all: " + data["case"]):
                # make sure clear_all calls clear_display
                cleardispcnt = self.clear_display.call_count

                self.run_basic_test(
                    func=self.calc_data.clear_all,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

                self.assertEqual((cleardispcnt + 1), self.clear_display.call_count)

    # clear_all doesn't take input, so there isn't an invalid input check


if __name__ == "__main__":
    unittest.main()
