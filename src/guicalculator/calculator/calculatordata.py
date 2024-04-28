"""
calculatordata.py - Data and functions used by the calculator.

Interface back to the gui is through passed in function calls:

    update_display    - Updates the calculation on the display
    clear_display     - Clears the calculator display entirely
    write_to_display  - Writes a message to the display
    bell              - Rings the bell for an error condition
    vars_popup        - Opens the variable popup window
"""

"""
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

from copy import deepcopy
from decimal import Decimal
from tkinter import StringVar
from typing import Callable

from ..globals import (
    DEFAULT_VARIABLES,
    CalculatorCommands,
    CalculatorFunctions,
    CalculatorSymbols,
    FunctionsType,
    VariablesType,
)
from .evaluate_calculation import evaluate_calculation
from .numtostr import numtostr
from .validate_user_var import validate_user_var


class CalculatorData:
    """CalculatorData - Data and functions used by the calculator"""

    # data used by the calculator
    _current_display_calc: str = ""  # the current caolculation to be displayed
    _current_eval_calc: str = ""  # the current calculation to be evalueated
    _current_input: str = ""  # the current number input

    _user_variables: VariablesType = VariablesType({})  # user defined variables

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

        self._memval = StringVar()  # the value stored in memory

    def validate_symbol_and_func(self, symbol: str, func: FunctionsType) -> None:
        """
        validate_symbol_and_func - Validate that symbol and func are valid.

        Parameters
        ----------
        symbol : str
            String to be added to the end of the calculation.
        func : FunctionsType
            Dataclass containing function to be added.

        Raises
        ------
        ValueError
            Used for custom errors, message indicates what the specific error was.
        """

        valid_symbols = [
            CalculatorSymbols.OPENPAREN,
            CalculatorSymbols.CLOSEPAREN,
            CalculatorSymbols.DIVISION,
            CalculatorSymbols.MULTIPLICATION,
            CalculatorSymbols.SUBTRACTION,
            CalculatorSymbols.ADDITION,
            CalculatorSymbols.SQUARE,
            CalculatorSymbols.EXPONENTIATION,
            *DEFAULT_VARIABLES.keys(),
        ]

        # double checking that variable names are str
        # default variables are defined in code so should be safe
        for v in self._user_variables.keys():
            if isinstance(v, str):
                valid_symbols.append(v)
            else:
                raise ValueError(f"User variable name is not str: {v!r}")

        valid_funcs = [
            CalculatorFunctions.NOFUNCTION,
            CalculatorFunctions.INVERSION,
            CalculatorFunctions.SQUAREROOT,
        ]

        if symbol:
            if not isinstance(symbol, str):
                raise ValueError(f"Symbol is wrong data type: {symbol!r}")

            if symbol not in valid_symbols:
                raise ValueError(f"Invalid symbol: {symbol!r}")

        if func:
            if not isinstance(func, FunctionsType):
                raise ValueError(
                    f"Function is not FunctionsType: {func!r}: {type(func)}"
                )

            if func not in valid_funcs:
                raise ValueError(f"Invalid function: {func!r}")

            if symbol and func != CalculatorFunctions.NOFUNCTION:
                raise ValueError(
                    f"Cannot specify both symbol and function: {symbol}, {func}"
                )

    def get_current_display_calc(
        self,
        symbol: str = "",
        func: FunctionsType = CalculatorFunctions.NOFUNCTION,
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
        func : FunctionsType, optional
            Optional dataclass containing function to be added, by default NOFUNCTION.

        Returns
        -------
        str
            The current displayed calculation.
        """

        self.validate_symbol_and_func(symbol, func)

        if self._current_input:
            inpt = numtostr(
                self.get_current_input(),
                commas=True,
                removeZeroes=False,
            )
            if self._current_input[-1] == ".":
                inpt += "."
        else:
            inpt = ""

        if func and func.display_func and inpt:
            if func == CalculatorFunctions.INVERSION:
                inpt = f"({func.display_func}{inpt})"
            else:
                inpt = f"{func.display_func}({inpt})"

        return_value = " ".join(
            filter(None, [self._current_display_calc, inpt, symbol])
        ).strip()
        return return_value

    def get_current_eval_calc(
        self,
        symbol: str = "",
        func: FunctionsType = CalculatorFunctions.NOFUNCTION,
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
        func : FunctionsType, optional
            Optional dataclass containing function to be added, by default NOFUNCTION.

        Returns
        -------
        str
            The calculation to be evaluated.
        """

        self.validate_symbol_and_func(symbol, func)

        if self._current_input:
            i = +self.get_current_input()
            inpt = f"Decimal({str(i)!r})"
        else:
            inpt = ""

        if func and func.eval_func and inpt:
            if func == CalculatorFunctions.INVERSION:
                inpt = f"({func.eval_func}{inpt})"
            else:
                inpt = f"{func.eval_func}({inpt})"

        return_value = " ".join([self._current_eval_calc, inpt, symbol]).strip()
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

        if self._current_input:
            return Decimal(self._current_input)
        else:
            return Decimal(0)

    def get_user_variables(self) -> VariablesType:
        """
        get_user_variables - Return a deepcopy of _user_variables

        Returns
        -------
        VariablesType
            A deepcopy of the _user_variables
        """
        return deepcopy(self._user_variables)

    def set_user_variables(self, user_variables: VariablesType) -> None:
        """
        set_user_variables - Set _user_variables
        """

        # this validation is duplicated from uservarseditfrm
        # but I don't want to leave the api vulnerable here
        # or lose the ability to identify the problem row there
        for nam, val in user_variables.items():
            validate_user_var(nam, val)

        self._user_variables = user_variables

    def update_current_calc(
        self,
        symbol: str = "",
        func: FunctionsType = CalculatorFunctions.NOFUNCTION,
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
        func : FunctionsType, optional
            Optional dataclass containing function to be added, by default NOFUNCTION.
        """

        self.validate_symbol_and_func(symbol, func)

        if self._current_input:  # if we have a value, round it
            self._current_input = numtostr(self.get_current_input())

        self._current_display_calc = self.get_current_display_calc(symbol, func)
        self._current_eval_calc = self.get_current_eval_calc(symbol, func)
        self._current_input = ""

        self.update_display()

    def process_button(
        self,
        buttoncmd: CalculatorCommands,
        buttontxt: str | int = "",
    ) -> None:
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
            can also be used to pass default or user variables, or
            calculator symbols like ** that aren't necessarily labels,
            by default ""
        """

        match buttoncmd:
            case CalculatorCommands.BASICBUTTON:
                self.button_press(buttontxt)

            case CalculatorCommands.BACKSPACE:
                self.backspace()

            case CalculatorCommands.CALCULATE:
                self.calculate()

            case CalculatorCommands.CLEARALL:
                self.clear_all()

            case CalculatorCommands.CLEARVALUE:
                self.clear_value()

            case CalculatorCommands.INVERSENUMBER:
                self.inverse_number()

            case CalculatorCommands.INVERTSIGN:
                self.invert_sign()

            case CalculatorCommands.MEMADD:
                self.memory_add()

            case CalculatorCommands.MEMCLEAR:
                self.memory_clear()

            case CalculatorCommands.MEMRECALL:
                self.memory_recall()

            case CalculatorCommands.MEMSTORE:
                self.memory_store()

            case CalculatorCommands.MEMSUBTRACT:
                self.memory_add(False)

            case CalculatorCommands.MEMSWAP:
                self.memory_swap()

            case CalculatorCommands.ROOTNUMBER:
                self.root_number()

            case CalculatorCommands.SQUARENUMBER:
                self.square_number()

            case CalculatorCommands.VARSPOPUP:
                self.vars_popup()

            case CalculatorCommands.XTOTHEY:
                self.button_press(CalculatorSymbols.EXPONENTIATION)

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
            self._current_input += str(symbol)
            self.update_display()

        elif symbol == ".":
            if symbol in self._current_input:
                self.bell()
                return

            self._current_input = (self._current_input or "0") + symbol
            self.update_display()

        else:
            self.update_current_calc(symbol)

    def backspace(self) -> None:
        """backspace - Erase last character from number being input."""

        if self._current_input:
            self._current_input = self._current_input[:-1]
        self.update_display()

    def clear_value(self) -> None:
        """
        clear_value - Clear the current number input, or if that is empty
        then clear the current calculation.
        """

        if self._current_input:
            self._current_input = ""
        else:
            self._current_display_calc = ""
            self._current_eval_calc = ""

        self.update_display()

    def clear_all(self) -> None:
        """
        clear_all - Clear the current number being input, the current
        calculation, and the display. Does not clear the value in memory.
        """

        self.clear_display()

        self._current_display_calc = ""
        self._current_eval_calc = ""
        self._current_input = ""

        self.update_display()

    def get_memval(self) -> StringVar:
        """
        get_memval - Returns the _memval variable. Needed for attaching to the
        ttk.Label in memdispfrm.py.

        Returns
        -------
        StringVar
            _memval variable
        """
        return self._memval

    def get_current_memory(self) -> Decimal:
        """
        get_current_memory - Get the current value stored in memory as a Decimal.

        Returns
        -------
        Decimal
            Decimal version of the value stored in memory. 0 if no value is
            currently stored in memory.
        """

        mem = self._memval.get().replace(",", "")
        if mem:
            return Decimal(mem)
        else:
            return Decimal(0)

    def memory_clear(self) -> None:
        """memory_clear - Clear the value stored in memory"""

        self._memval.set("")

    def memory_recall(self) -> None:
        """
        memory_recall - Replace the current number being input with the value
        stored in memory.
        """

        cur_mem = numtostr(self.get_current_memory())
        self._current_input = cur_mem
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
        self._current_input = numtostr(cur_val)
        self.update_display()

        # store it
        self._memval.set(numtostr(cur_val, commas=True))

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
        self._current_input = numtostr(self.get_current_memory())

        # store retrieved current value in memory
        self._memval.set(cur_num)

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
        self._current_input = numtostr(cur_val)
        self.update_display()

        # get current memory
        cur_mem = self.get_current_memory()

        # add (or subtract)
        mv = cur_mem + (cur_val * sign)
        self._memval.set(numtostr(mv, commas=True))

    def invert_sign(self) -> None:
        """
        invert_sign - Convert the current number being input from positive to
        negative or negative to positive: -x.

        Notes
        -----
        As a side effect, will round the number currently being input to the
        precision in the Decimal context.
        """

        if self._current_input:
            self._current_input = numtostr(-self.get_current_input())
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

        if self._current_input:
            self.update_current_calc(func=CalculatorFunctions.INVERSION)
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

        self.update_current_calc(CalculatorSymbols.SQUARE)
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

        if self._current_input:
            self.update_current_calc(func=CalculatorFunctions.SQUAREROOT)
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
        if self._current_eval_calc:
            try:
                # run the current calculation
                val = evaluate_calculation(
                    self._current_eval_calc,
                    self._user_variables,
                )

                # show the result
                self.write_to_display(f" = {numtostr(val, commas=True)}\n{'=' * 30}\n")

                # clear current calc and set current input to result
                self._current_display_calc = ""
                self._current_eval_calc = ""
                self._current_input = numtostr(val)

            except Exception as error:
                # should probably use a logger
                print(f"ERROR: {error}\n")

                # clear the current calculation and print the error message
                self.write_to_display(f"=== ERROR ===\n")

                self._current_display_calc = ""
                self._current_eval_calc = ""
                self._current_input = ""

        # update the display
        self.update_display()
