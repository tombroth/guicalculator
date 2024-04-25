import tkinter
import unittest
from decimal import Decimal, InvalidOperation
from io import StringIO
from typing import Any, Callable
from unittest.mock import MagicMock, patch

from guicalculator.calculatordata import CalculatorData  # type: ignore
from guicalculator.globals import PI  # type: ignore


class CalculatorDataTest(unittest.TestCase):

    root = tkinter.Tk()  # needed to instantiate the StringVar

    # functions to mock
    update_display = MagicMock()
    clear_display = MagicMock()
    write_to_display = MagicMock()
    bell = MagicMock()
    vars_popup = MagicMock()

    calc_data = CalculatorData(
        update_display,
        clear_display,
        write_to_display,
        bell,
        vars_popup,
    )

    def set_current_disp_eval_inpt(self, cur_vals: dict) -> None:
        """
        set_current_display_eval_input - Sets the variables in calc_data.

        The keys used from cur_vals are:

        * "disp" - current_display_calc
        * "eval" - current_eval_calc
        * "inpt" - current_input
        * "mem" - memval - the value stored in memory
        * "vars" - user_variables

        Parameters
        ----------
        cur_vals : dict
            A dictionary with the values for the variables
        """

        if "disp" in cur_vals:
            self.calc_data.current_display_calc = cur_vals["disp"]
        if "eval" in cur_vals:
            self.calc_data.current_eval_calc = cur_vals["eval"]
        if "inpt" in cur_vals:
            self.calc_data.current_input = cur_vals["inpt"]
        if "mem" in cur_vals:
            self.calc_data.memval.set(cur_vals["mem"])
        if "vars" in cur_vals:
            self.calc_data.user_variables = cur_vals["vars"]

    def chk_current_disp_eval_inpt(self, cur_vals: dict) -> None:
        """
        chk_current_disp_eval_inpt - Asserts the values of the variables
        in calc_data are what they should be.

        The keys used from cur_vals are:

        * "disp" - current_display_calc
        * "eval" - current_eval_calc
        * "inpt" - current_input
        * "mem" - memval - the value stored in memory
        * "vars" - user_variables

        Parameters
        ----------
        cur_vals : dict
            A dictionary with the values to check the variables against
        """

        if "disp" in cur_vals:
            self.assertEqual(
                self.calc_data.current_display_calc,
                cur_vals["disp"],
                "current_display_calc",
            )
        if "eval" in cur_vals:
            self.assertEqual(
                self.calc_data.current_eval_calc,
                cur_vals["eval"],
                "current_eval_calc",
            )
        if "inpt" in cur_vals:
            self.assertEqual(
                self.calc_data.current_input,
                cur_vals["inpt"],
                "current_input",
            )
        if "mem" in cur_vals:
            self.assertEqual(
                self.calc_data.memval.get(),
                cur_vals["mem"],
                "memval",
            )
        if "vars" in cur_vals:
            self.assertEqual(
                self.calc_data.user_variables,
                cur_vals["vars"],
                "user_variables",
            )

    def run_basic_test(
        self, func: Callable, cur_vals: dict, params: dict = {}, end_vals: dict = {}
    ) -> Any:
        """
        run_basic_test - Runs a basic test that

        1. Sets the current_display_calc, current_eval_calc, and current_input
        variables to the values in cur_vals.
        2. Executes the function, passing any parameters from params.
        3. Checks the values in current_display_calc, current_eval_calc, and
        current_input variables against end_vals.
        4. Returns any result from the function.


        Parameters
        ----------
        func : Callable
            The function to execute
        cur_vals : dict
            Current values passed to set_current_disp_eval_inpt function
        params : dict, optional
            Function parameters passed as **params, by default {}
        end_vals : dict, optional
            Ending values passed to chk_current_disp_eval_inpt function, by default {}

        Returns
        -------
        Any
            return value from function
        """

        self.set_current_disp_eval_inpt(cur_vals)
        res = func(**params)
        if end_vals:
            self.chk_current_disp_eval_inpt(end_vals)
        return res

    def test_validate_symbol_and_func(self):
        """Test the validate_symbol_and_func function."""

        test_data = [
            {
                "case": "Both parameters empty",
                "params": {
                    "symbol": "",
                    "func": ("", ""),
                },
            },
            {
                "case": "(",
                "params": {
                    "symbol": "(",
                    "func": ("", ""),
                },
            },
            {
                "case": ")",
                "params": {
                    "symbol": ")",
                    "func": ("", ""),
                },
            },
            {
                "case": "/",
                "params": {
                    "symbol": "/",
                    "func": ("", ""),
                },
            },
            {
                "case": "*",
                "params": {
                    "symbol": "*",
                    "func": ("", ""),
                },
            },
            {
                "case": "-",
                "params": {
                    "symbol": "-",
                    "func": ("", ""),
                },
            },
            {
                "case": "+",
                "params": {
                    "symbol": "+",
                    "func": ("", ""),
                },
            },
            {
                "case": "** 2",
                "params": {
                    "symbol": "** 2",
                    "func": ("", ""),
                },
            },
            {
                "case": "**",
                "params": {
                    "symbol": "**",
                    "func": ("", ""),
                },
            },
            {
                "case": "1/",
                "params": {
                    "symbol": "",
                    "func": ("1/", "1/"),
                },
            },
            {
                "case": "sqrt",
                "params": {
                    "symbol": "",
                    "func": ("sqrt", "Decimal.sqrt"),
                },
            },
        ]

        for data in test_data:
            with self.subTest(msg="validate_symbol_and_func: " + data["case"]):
                self.calc_data.validate_symbol_and_func(**data["params"])

    def test_validate_symbol_and_func_invalid_input(self):
        """Test the validate_symbol_and_func function with invalid input."""

        test_data = [
            {
                "case": "Both parameters used",
                "params": {
                    "symbol": "+",
                    "func": ("1/", "1/"),
                },
                "result": ValueError,
            },
            {
                "case": "Symbol not a str",
                "params": {
                    "symbol": ["+", "-"],
                    "func": ("", ""),
                },
                "result": ValueError,
            },
            {
                "case": "Symbol not valid",
                "params": {
                    "symbol": "+-*/",
                    "func": ("", ""),
                },
                "result": ValueError,
            },
            {
                "case": "More than two elements in func tuple",
                "params": {
                    "symbol": "",
                    "func": ("1/", "1/", "1/"),
                },
                "result": ValueError,
            },
            {
                "case": "Only one element in func tuple",
                "params": {
                    "symbol": "",
                    "func": ("1/"),
                },
                "result": ValueError,
            },
            {
                "case": "Elements in func tuple not str",
                "params": {
                    "symbol": "",
                    "func": (1, 1),
                },
                "result": ValueError,
            },
            {
                "case": "Invalid func tuple #1",
                "params": {
                    "symbol": "",
                    "func": ("1/", "sqrt"),
                },
                "result": ValueError,
            },
            {
                "case": "Invalid func tuple #2",
                "params": {
                    "symbol": "",
                    "func": ("print", "print"),
                },
                "result": ValueError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="validate_symbol_and_func: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.calc_data.validate_symbol_and_func(**data["params"])

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
                "params": {"func": ("sqrt", "Decimal.sqrt")},
                "result": "sqrt(123)",
            },
            {
                "case": "Inversion: (1/3)",
                "current": {"disp": "", "eval": "", "inpt": "3"},
                "params": {"func": ("1/", "1/")},
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
                    "func": ("1/", "1/"),
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

    def test_get_current_eval_calc(self):
        """Test the get_current_eval_calc function."""

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
                "result": "Decimal('123')",
            },
            {
                "case": "123 ** 2",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": "** 2"},
                "result": "Decimal('123') ** 2",
            },
            {
                "case": "sqrt(123)",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"func": ("sqrt", "Decimal.sqrt")},
                "result": "Decimal.sqrt(Decimal('123'))",
            },
            {
                "case": "Inversion: (1/3)",
                "current": {"disp": "", "eval": "", "inpt": "3"},
                "params": {"func": ("1/", "1/")},
                "result": "(1/Decimal('3'))",
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_eval_calc: " + data["case"]):
                res = self.run_basic_test(
                    func=self.calc_data.get_current_eval_calc,
                    cur_vals=data["current"],
                    params=data["params"],
                    end_vals=data["current"],
                )
                self.assertEqual(res, data["result"])

    def test_get_current_eval_calc_invalid_input(self):
        """Test the get_current_eval_calc function with invalid input."""

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
                    "func": ("1/", "1/"),
                },
                "result": ValueError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_eval_calc: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.get_current_eval_calc,
                        cur_vals=data["current"],
                        params=data["params"],
                    )

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
                "params": {"func": ("sqrt", "Decimal.sqrt")},
                "ending": {
                    "disp": "sqrt(123)",
                    "eval": "Decimal.sqrt(Decimal('123'))",
                    "inpt": "",
                },
            },
            {
                "case": "Inversion: (1/3)",
                "current": {"disp": "", "eval": "", "inpt": "3"},
                "params": {"func": ("1/", "1/")},
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
                    "func": ("1/", "1/"),
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

    # skipping this for now, it's just a big match/case statement to call other functions
    # def test_process_button(self):
    #     pass

    def test_process_button_invalid_input(self):
        """Test the process_button function with invalid input."""

        """
        passing invalid buttontxt with the "button" command 
        get passed through process_button and button_press
        but get caught in update_current_calc when it 
        calls validate_symbol_and_func, and it raises an
        error. We already have tests to catch that
        condition in validate_symbol_and_func.
        """
        test_data = [
            {
                "case": "Unknown function Call",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "params": {"buttoncmd": "UnknownFunctionCall"},
            },
            {
                "case": "Passing int instead of str",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "params": {"buttoncmd": 123},
            },
            {
                "case": "Passing empty string",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "params": {"buttoncmd": ""},
            },
            {
                "case": "Passing None",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "params": {"buttoncmd": None},
            },
        ]

        for data in test_data:
            with self.subTest(msg="process_button: " + data["case"]):
                with patch("sys.stdout", new=StringIO()) as fake_out:
                    self.run_basic_test(
                        func=self.calc_data.process_button,
                        cur_vals=data["current"],
                        params=data["params"],
                    )
                    expected_out = f"Unknown command: {data["params"]["buttoncmd"]!r}\n"
                    self.assertEqual(fake_out.getvalue(), expected_out)

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

    def test_get_current_memory(self):
        """Test the get_current_memory function."""

        test_data = [
            {
                "case": "123",
                "current": {"mem": "123"},
                "ending": {"mem": "123"},
                "result": Decimal("123"),
            },
            {
                "case": "1,234.56",
                "current": {"mem": "1,234.56"},
                "ending": {"mem": "1,234.56"},
                "result": Decimal("1234.56"),
            },
            {
                "case": "Value not set",
                "current": {"mem": ""},
                "ending": {"mem": ""},
                "result": Decimal("0"),
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_memory: " + data["case"]):
                res = self.run_basic_test(
                    func=self.calc_data.get_current_memory,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )
                self.assertEqual(res, data["result"])

    def test_get_current_memory_invalid_input(self):
        """Test the get_current_memory function with invalid data."""

        test_data = [
            {
                "case": "Invalid value in mem",
                "current": {"mem": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack",
                "current": {"mem": lambda: __import__("os").system("dir")},
                "result": InvalidOperation,
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_memory: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.get_current_memory,
                        cur_vals=data["current"],
                    )

    def test_memory_clear(self):
        """Test the memory_clear function"""

        test_data = [
            {
                "case": "No value in memory",
                "current": {"mem": ""},
                "ending": {"mem": ""},
            },
            {
                "case": "123",
                "current": {"mem": "123"},
                "ending": {"mem": ""},
            },
            {
                "case": "1,234.56",
                "current": {"mem": "1,234.56"},
                "ending": {"mem": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_clear: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.memory_clear,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    # memory_clear doesn't take input, so there isn't an invalid input check

    def test_memory_recall(self):
        """Test the memory_recall function."""

        test_data = [
            {
                "case": "No value in memory",
                "current": {"mem": "", "inpt": "321"},
                "ending": {"mem": "", "inpt": "0"},
            },
            {
                "case": "123",
                "current": {"mem": "123", "inpt": "321"},
                "ending": {"mem": "123", "inpt": "123"},
            },
            {
                "case": "1,234.56",
                "current": {"mem": "1,234.56", "inpt": "321"},
                "ending": {"mem": "1,234.56", "inpt": "1234.56"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_recall: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.memory_recall,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_memory_recall_invalid_input(self):
        """Test the memory_recall function with invalid input."""

        test_data = [
            {
                "case": "Invalid value in mem",
                "current": {"mem": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack",
                "current": {"mem": lambda: __import__("os").system("dir")},
                "result": InvalidOperation,
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_recall: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.memory_recall,
                        cur_vals=data["current"],
                    )

    def test_memory_store(self):
        """Test the memory_store function."""

        test_data = [
            {
                "case": "No value in memory, value in input",
                "current": {"mem": "", "inpt": "321"},
                "ending": {"mem": "321", "inpt": "321"},
            },
            {
                "case": "No value in memory, no value in input",
                "current": {"mem": "", "inpt": ""},
                "ending": {"mem": "0", "inpt": "0"},
            },
            {
                "case": "Value in memory, no value in input",
                "current": {"mem": "123", "inpt": ""},
                "ending": {"mem": "0", "inpt": "0"},
            },
            {
                "case": "321 overwrites 123",
                "current": {"mem": "123", "inpt": "321"},
                "ending": {"mem": "321", "inpt": "321"},
            },
            {
                "case": "1,234.56 overwrites 123",
                "current": {"mem": "123", "inpt": "1234.56"},
                "ending": {"mem": "1,234.56", "inpt": "1234.56"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_store: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.memory_store,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_memory_store_invalid_input(self):
        """Test the memory_store function with invalid input."""

        test_data = [
            {
                "case": "Invalid value in input",
                "current": {"mem": "", "inpt": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack",
                "current": {
                    "mem": "",
                    "inpt": lambda: __import__("os").system("dir"),
                },
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_store: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.memory_store,
                        cur_vals=data["current"],
                    )

    def test_memory_swap(self):
        """Test the memory_swap function."""

        test_data = [
            {
                "case": "No value in memory, value in input",
                "current": {"mem": "", "inpt": "321"},
                "ending": {"mem": "321", "inpt": "0"},
            },
            {
                "case": "No value in memory, no value in input",
                "current": {"mem": "", "inpt": ""},
                "ending": {"mem": "0", "inpt": "0"},
            },
            {
                "case": "Value in memory, no value in input",
                "current": {"mem": "123", "inpt": ""},
                "ending": {"mem": "0", "inpt": "123"},
            },
            {
                "case": "321 swaps with 123",
                "current": {"mem": "123", "inpt": "321"},
                "ending": {"mem": "321", "inpt": "123"},
            },
            {
                "case": "1,234.56 swaps with 123",
                "current": {"mem": "123", "inpt": "1234.56"},
                "ending": {"mem": "1,234.56", "inpt": "123"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_swap: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.memory_swap,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_memory_swap_invalid_input(self):
        """Test the memory_swap function with invalid input."""

        test_data = [
            {
                "case": "Invalid value in input",
                "current": {"mem": "", "inpt": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack in input",
                "current": {
                    "mem": "",
                    "inpt": lambda: __import__("os").system("dir"),
                },
                "result": TypeError,
            },
            {
                "case": "Invalid value in memory",
                "current": {"inpt": "", "mem": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack in memory",
                "current": {
                    "inpt": "",
                    "mem": lambda: __import__("os").system("dir"),
                },
                "result": InvalidOperation,
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_swap: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.memory_swap,
                        cur_vals=data["current"],
                    )

    def test_memory_add(self):
        """Test the memory_add function."""

        test_data = [
            {
                "case": "No value in memory, value in input",
                "current": {"mem": "", "inpt": "321"},
                "params": {},
                "ending": {"mem": "321", "inpt": "321"},
            },
            {
                "case": "No value in memory, no value in input",
                "current": {"mem": "", "inpt": ""},
                "params": {},
                "ending": {"mem": "0", "inpt": "0"},
            },
            {
                "case": "Value in memory, no value in input",
                "current": {"mem": "123", "inpt": ""},
                "params": {},
                "ending": {"mem": "123", "inpt": "0"},
            },
            {
                "case": "321 added to 123",
                "current": {"mem": "123", "inpt": "321"},
                "params": {},
                "ending": {"mem": "444", "inpt": "321"},
            },
            {
                "case": "321 subtracted from 123",
                "current": {"mem": "123", "inpt": "321"},
                "params": {"addto": False},
                "ending": {"mem": "-198", "inpt": "321"},
            },
            {
                "case": "1,234.56 subtracted from 123",
                "current": {"mem": "123", "inpt": "1234.56"},
                "params": {"addto": False},
                "ending": {"mem": "-1,111.56", "inpt": "1234.56"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_add: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.memory_add,
                    cur_vals=data["current"],
                    params=data["params"],
                    end_vals=data["ending"],
                )

    def test_memory_add_invalid_input(self):
        """Test the memory_add function with invalid input."""

        test_data = [
            {
                "case": "Invalid value in input",
                "current": {"mem": "", "inpt": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack in input",
                "current": {
                    "mem": "",
                    "inpt": lambda: __import__("os").system("dir"),
                },
                "result": TypeError,
            },
            {
                "case": "Invalid value in memory",
                "current": {"inpt": "", "mem": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack in memory",
                "current": {
                    "inpt": "",
                    "mem": lambda: __import__("os").system("dir"),
                },
                "result": InvalidOperation,
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_add: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.memory_add,
                        cur_vals=data["current"],
                    )

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

    def test_square_number(self):
        """Test the square_number function."""

        test_data = [
            {
                "case": "2 as str",
                "current": {"disp": "", "eval": "", "inpt": "2"},
                "ending": {"disp": "2 ** 2", "eval": "Decimal('2') ** 2", "inpt": ""},
            },
            {
                "case": "2 as int",
                "current": {"disp": "", "eval": "", "inpt": 2},
                "ending": {"disp": "2 ** 2", "eval": "Decimal('2') ** 2", "inpt": ""},
            },
            {
                "case": "No input value",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "ending": {"disp": "** 2", "eval": "** 2", "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="square_number: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.square_number,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_square_number_invalid_input(self):
        """Test the square_number function with invalid input."""

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
            with self.subTest(msg="square_number: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.square_number,
                        cur_vals=data["current"],
                    )

    def test_root_number(self):
        """Test the root_number function."""

        test_data = [
            {
                "case": "2 as str",
                "current": {"disp": "", "eval": "", "inpt": "2"},
                "ending": {
                    "disp": "sqrt(2)",
                    "eval": "Decimal.sqrt(Decimal('2'))",
                    "inpt": "",
                },
            },
            {
                "case": "2 as int",
                "current": {"disp": "", "eval": "", "inpt": 2},
                "ending": {
                    "disp": "sqrt(2)",
                    "eval": "Decimal.sqrt(Decimal('2'))",
                    "inpt": "",
                },
            },
            {
                "case": "No input value",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "ending": {"disp": "", "eval": "", "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="root_number: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.root_number,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_root_number_invalid_input(self):
        """Test the root_number function with invalid input."""

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
            with self.subTest(msg="root_number: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.root_number,
                        cur_vals=data["current"],
                    )

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
                "ending": {"disp": "", "eval": "", "inpt": "2.718281828459045235360287471"},
            },
            {
                "case": "Default Variable PI",
                "current": {"disp": PI, "eval": PI, "inpt": ""},
                "ending": {"disp": "", "eval": "", "inpt": "3.141592653589793238462643383"},
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
