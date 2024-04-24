"""
calculatordata.py - Data and functions used by the calculator.

Interface back to the gui is through passed in function calls:

    update_display    - Updates the calculation on the display
    clear_display     - Clears the calculator display entirely
    write_to_display  - Writes a message to the display
    bell              - Rings the bell for an error condition
    vars_popup        - Opens the variable popup window


Copyright (c) 2024 Thomas Brotherton

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from decimal import Decimal
from tkinter import StringVar
from typing import Callable

from .globals import VariablesType
from .supportfuncs import evaluate_calculation, numtostr


class CalculatorData:
    """CalculatorData - Data and functions used by the calculator"""

    # data used by the calculator
    current_display_calc: str = ""  # the current caolculation to be displayed
    current_eval_calc: str = ""  # the current calculation to be evalueated
    current_input: str = ""  # the current number input

    user_variables: VariablesType = VariablesType({})  # user defined variables

    def __init__(
        self,
        update_display: Callable[[], None],
        clear_display: Callable[[], None],
        write_to_display: Callable[[str], None],
        bell: Callable[[], None],
        vars_popup: Callable[[], None],
    ) -> None:
        self.update_display = update_display
        self.clear_display = clear_display
        self.write_to_display = write_to_display
        self.bell = bell
        self.vars_popup = vars_popup

        self.memval = StringVar()  # the value stored in memory

    def validate_symbol_and_func(self, symbol: str, func: tuple[str, str]) -> None:
        """
        validate_symbol_and_func - Validate that symbol and func are valid.

        Parameters
        ----------
        symbol : str
            String to be added to the end of the calculation.
        func : tuple[str, str]
            Tuple containing function to be added.
            [0] is for the display version of the calculation
            [1] is for the evaluation version of the calculation

        Raises
        ------
        ValueError
            Used for custom errors, message indicates what the specific error was.
        """

        if symbol:
            if type(symbol) != str:
                raise ValueError(f"Symbol is not str type: {symbol!r}")
            if symbol not in ["(", ")", "/", "*", "-", "+", "** 2", "**"]:
                raise ValueError(f"Invalid symbol: {symbol!r}")

        if func:
            if type(func) != tuple:
                raise ValueError(
                    f"Function is not tuple[str, str]: {func!r}: {type(func)}"
                )
            if func not in [("", ""), ("1/", "1/"), ("sqrt", "Decimal.sqrt")]:
                raise ValueError(f"Invalid function: {func!r}")
            if symbol and func != ("", ""):
                raise ValueError(
                    f"Cannot specify both symbol and function: {symbol}, {func}"
                )

    def get_current_display_calc(
        self, symbol: str = "", func: tuple[str, str] = ("", "")
    ) -> str:
        """
        get_current_display_calc - Get the current displayed calculation.

        Get the current displayed calculation, including current number input
        and optional mathematical operator.

        Parameters
        ----------
        symbol : str, optional
            Optional string to be added to the end of the calculation. Normally
            will be blank or a mathematical operator, by default "".
        func : tuple[str, str], optional
            Optional tuple containing function to be added, by default ("", "").
            [0] is for the display version of the calculation
            [1] is for the evaluation version of the calculation

        Returns
        -------
        str
            The current displayed calculation.
        """

        self.validate_symbol_and_func(symbol, func)

        if self.current_input:
            inpt = numtostr(
                self.get_current_input(),
                commas=True,
                removeZeroes=False,
            )
            if self.current_input[-1] == ".":
                inpt += "."
        else:
            inpt = ""

        if func and func[0] and inpt:
            if func[0] == "1/":
                inpt = f"({func[0]}{inpt})"
            else:
                inpt = f"{func[0]}({inpt})"

        return_value = " ".join(
            filter(None, [self.current_display_calc, inpt, symbol])
        ).strip()
        return return_value

    def get_current_eval_calc(
        self, symbol: str = "", func: tuple[str, str] = ("", "")
    ) -> str:
        """
        get_current_eval_calc - Get the current calculation to be evaluated.

        Get the current calculation to be evaluated, including current number
        input and optional mathematical operator. The primary difference from
        get_current_display_calc is that the number inputs are surrounded by
        calls to Decimal to convert int and float inputs into Decimal to avoid
        decimal to binary and back to decimal rounding errors. In other words
        0.3 - 0.2 should be 0.1, not 0.09999999999999998.

        Parameters
        ----------
        symbol : str, optional
            Optional string to be added to the end of the calculation. Normally
            will be blank or a mathematical operator, by default "".
        func : tuple[str, str], optional
            Optional tuple containing function to be added, by default ("", "").
            [0] is for the display version of the calculation
            [1] is for the evaluation version of the calculation

        Returns
        -------
        str
            The calculation to be evaluated.
        """

        self.validate_symbol_and_func(symbol, func)

        if self.current_input:
            i = +self.get_current_input()
            inpt = f"Decimal({str(i)!r})"
        else:
            inpt = ""

        if func and func[1] and inpt:
            if func[1] == "1/":
                inpt = f"({func[1]}{inpt})"
            else:
                inpt = f"{func[1]}({inpt})"

        return_value = " ".join([self.current_eval_calc, inpt, symbol]).strip()
        return return_value

    def get_current_input(self) -> Decimal:
        """
        get_current_input - Get current number input as a Decimal.

        Returns
        -------
        Decimal
            Decimal version of the number currently being input. 0 if no
            number is currently being input.
        """

        if self.current_input:
            return Decimal(self.current_input)
        else:
            return Decimal(0)

    def update_current_calc(
        self, symbol: str = "", func: tuple[str, str] = ("", "")
    ) -> None:
        """
        update_current_calc - Update the current calculation being input.

        Uses get_current_display_calc and get_current_eval_calc to generate
        the most recent versions of the calculation being input (including
        the current number being input and the operator being input passed
        in by symbol) and stores them in globals.current_display_calc and
        globals.current_eval_calc. Then calls update_display.

        Notes
        -----
        As a side effect, will round the number currently being input to the
        precision in the Decimal context.

        Parameters
        ----------
        symbol : str, optional
            Optional string to be added to the end of the calculation. Normally
            will be blank or a mathematical operator, by default "".
        func : tuple[str, str], optional
            Optional tuple containing function to be added, by default ("", "").
            [0] is for the display version of the calculation
            [1] is for the evaluation version of the calculation
        """

        self.validate_symbol_and_func(symbol, func)

        if self.current_input:  # if we have a value, round it
            self.current_input = numtostr(self.get_current_input())

        self.current_display_calc = self.get_current_display_calc(symbol, func)
        self.current_eval_calc = self.get_current_eval_calc(symbol, func)
        self.current_input = ""

        self.update_display()

    def process_button(self, buttoncmd: str, buttontxt: str | int = "") -> None:
        """
        process_button - Process a calculator button press.

        Parameters
        ----------
        buttoncmd : str
            The command string from the ButtonInfo dictionary in
            buttoncfg.py buttons.
        buttontxt : str | int, optional
            For buttons in buttoncfg.py that don't have a command
            (number and basic math symbols) this is the button label,
            by default ""
        """

        match buttoncmd:
            case "button":
                self.button_press(buttontxt)

            case "backspace":
                self.backspace()

            case "calculate":
                self.calculate()

            case "clearAll":
                self.clear_all()

            case "clearValue":
                self.clear_value()

            case "inverseNumber":
                self.inverse_number()

            case "invertSign":
                self.invert_sign()

            case "memAdd":
                self.memory_add()

            case "memClear":
                self.memory_clear()

            case "memRecall":
                self.memory_recall()

            case "memStore":
                self.memory_store()

            case "memSubtract":
                self.memory_add(False)

            case "memSwap":
                self.memory_swap()

            case "rootNumber":
                self.root_number()

            case "squareNumber":
                self.square_number()

            case "varsPopup":
                self.vars_popup()

            case "xToTheY":
                self.button_press("**")
            case _:
                self.bell()
                print(f"Unknown command: {buttoncmd!r}")

    def button_press(self, symbol: str | int) -> None:
        """
        button_press - Handles simple button presses.

        Handles simple button presses that just add to the current formula. For
        example, a digit (passed as int, not str), ".", "+", "-", etc. Does not
        handle complex things like manipulating the value stored in memory.

        Notes
        -----
        As a side effect, will round the number currently being input to the
        precision in the Decimal context if symbol is not a digit or decimal
        point.

        Parameters
        ----------
        symbol : str | int
            The digit or mathematical operator being processed.
        """

        if isinstance(symbol, int):
            self.current_input += str(symbol)
            self.update_display()

        elif symbol == ".":
            if symbol in self.current_input:
                self.bell()
                return

            self.current_input = (self.current_input or "0") + symbol
            self.update_display()

        else:
            self.update_current_calc(symbol)

    def backspace(self) -> None:
        """backspace - Erase last character from number being input."""

        if self.current_input:
            self.current_input = self.current_input[:-1]
        self.update_display()

    def clear_value(self) -> None:
        """
        clear_value - Clear the current number input, or if that is empty
        then clear the current calculation.
        """

        if self.current_input:
            self.current_input = ""
        else:
            self.current_display_calc = ""
            self.current_eval_calc = ""

        self.update_display()

    def clear_all(self) -> None:
        """
        clear_all - Clear the current number being input, the current
        calculation, and the display. Does not clear the value in memory.
        """

        self.clear_display()

        self.current_display_calc = ""
        self.current_eval_calc = ""
        self.current_input = ""

        self.update_display()

    def get_current_memory(self) -> Decimal:
        """
        get_current_memory - Get the current value stored in memory as a Decimal.

        Returns
        -------
        Decimal
            Decimal version of the value stored in memory. 0 if no value is
            currently stored in memory.
        """

        mem = self.memval.get().replace(",", "")
        if mem:
            return Decimal(mem)
        else:
            return Decimal(0)

    def memory_clear(self) -> None:
        """memory_clear - Clear the value stored in memory"""

        self.memval.set("")

    def memory_recall(self) -> None:
        """
        memory_recall - Replace the current number being input with the value
        stored in memory.
        """

        cur_mem = numtostr(self.get_current_memory())
        self.current_input = cur_mem
        self.update_display()

    def memory_store(self) -> None:
        """
        memory_store - Change the value stored in memory to be the same as the
        current number being input.

        Notes
        -----
        Cannot do a simple set because we round and format the display.

        As a side effect, will round the number currently being input to the
        precision in the Decimal context.
        """

        # get and reformat current value
        cur_val = +self.get_current_input()
        self.current_input = numtostr(cur_val)
        self.update_display()

        # store it
        self.memval.set(numtostr(cur_val, commas=True))

    def memory_swap(self) -> None:
        """
        memory_swap - Swap the value stored in memory with the current number
        being input.

        Notes
        -----
        Cannot do a simple swap like (a,b) = (b,a) because we need to cal .set
        on the tk.StringVar that stores the memory value, and we round and
        format the display.

        As a side effect, will round the number currently being input to the
        precision in the Decimal context.
        """

        # get current value (formatted with commas)
        cur_num = numtostr(self.get_current_input(), commas=True)

        # store memory in current value
        self.current_input = numtostr(self.get_current_memory())

        # store retrieved current value in memory
        self.memval.set(cur_num)

        self.update_display()

    def memory_add(self, addto: bool = True) -> None:
        """
        memory_add - Add or subtract the current number being input to or from
        the value stored in memory.

        Notes
        -----
        If addto is passed in as false, will subtract the value being input
        from memory by multiplying the value by -1 before adding.

        As a side effect, will round the number currently being input to the
        precision in the Decimal context.

        Parameters
        ----------
        addto : bool, optional
            If true, performs addition. If false, performs subtraction.
            By default True.
        """

        # adding or subtracting
        if addto:
            sign = Decimal(1)
        else:
            sign = Decimal(-1)

        # get the current input number (and reformat it)
        cur_val = +self.get_current_input()
        self.current_input = numtostr(cur_val)
        self.update_display()

        # get current memory
        cur_mem = self.get_current_memory()

        # add (or subtract)
        mv = cur_mem + (cur_val * sign)
        self.memval.set(numtostr(mv, commas=True))

    def invert_sign(self) -> None:
        """
        invert_sign - Convert the current number being input from positive to
        negative or negative to positive: -x.

        Notes
        -----
        As a side effect, will round the number currently being input to the
        precision in the Decimal context.
        """

        if self.current_input:
            self.current_input = numtostr(-self.get_current_input())
        self.update_display()

    def inverse_number(self) -> None:
        """
        inverse_number - Convert the current number being input to it's
        mathematical inverse: 1/x.

        Notes
        -----
        As a side effect, will round the number currently being input to the
        precision in the Decimal context.
        """

        if self.current_input:
            self.update_current_calc(func=("1/", "1/"))
        self.update_display()

    def square_number(self) -> None:
        """
        square_number - Convert the current number being input to its
        square: x**2.

        Notes
        -----
        As a side effect, will round the number currently being input to the
        precision in the Decimal context.
        """

        self.update_current_calc("** 2")
        self.update_display()

    def root_number(self) -> None:
        """
        root_number - Convert the current number being input to its
        square root: Decimal.sqrt(x).

        Notes
        -----
        As a side effect, will round the number currently being input to the
        precision in the Decimal context.
        """

        if self.current_input:
            self.update_current_calc(func=("sqrt", "Decimal.sqrt"))
            # self.current_input = numtostr(Decimal.sqrt(self.get_current_input()))
        self.update_display()

    def calculate(self) -> None:
        """
        calculate - Performs the current calculation and updates the display
        with the results.
        """

        # update current calc and display
        self.update_current_calc()

        # if we have a calculation to perform
        if self.current_eval_calc:
            try:
                # run the current calculation
                val = evaluate_calculation(
                    self.current_eval_calc,
                    self.user_variables,
                )

                # show the result
                self.write_to_display(f" ={numtostr(val, commas=True)}\n{'=' * 30}\n")

                # clear current calc and set current input to result
                self.current_display_calc = ""
                self.current_eval_calc = ""
                self.current_input = numtostr(val)

            except Exception as error:
                # should probably use a logger
                print(f"ERROR: {error}\n")

                # clear the current calculation and print the error message
                self.write_to_display(f"=== ERROR ===\n")

                self.current_display_calc = ""
                self.current_eval_calc = ""
                self.current_input = ""

        # update the display
        self.update_display()
