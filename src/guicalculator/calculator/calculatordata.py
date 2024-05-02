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

from abc import ABC, abstractmethod
from copy import deepcopy
from decimal import Decimal
from tkinter import StringVar, ttk
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
from .logwrapper import logerror, object_wrapper
from .numtostr import numtostr
from .validate_user_var import validate_user_vars


class _CalcStringBase(ABC):
    """
    _CalcStringBase - An internal Abstract Base Class to represent an entry 
    in the _current_calc list.
    """

    @abstractmethod
    def get_disp(self) -> str: ...

    @abstractmethod
    def get_eval(self) -> str: ...

    @abstractmethod
    def __eq__(self, other) -> bool: ...

    def __str__(self) -> str:
        return self.get_disp()

    def __repr__(self) -> str:
        return self.get_eval()


class _CalcStringNumber(_CalcStringBase):
    """
    _CalcStringNumber - An internal class to represent a numeric value
    (stored as a Decimal) in the _current_calc list.
    """

    def __init__(
        self, thenum: Decimal | int | float | str, decimal_point: bool = False
    ) -> None:
        if isinstance(thenum, Decimal):
            self._thenum = thenum
        elif isinstance(thenum, int) or isinstance(thenum, float):
            self._thenum = Decimal(thenum)
        elif isinstance(thenum, str):
            self._thenum = Decimal(thenum.replace(",", ""))
        else:
            raise ValueError(f"Invalid type for number: {type(thenum)}")
        self._decimal_point = decimal_point

    def __eq__(self, other) -> bool:
        return isinstance(other, _CalcStringNumber) and self._thenum == other._thenum

    def get_disp(self) -> str:
        x = "{0:,f}".format(self._thenum)
        if self._decimal_point:
            x += "."
        return x

    def get_eval(self) -> str:
        x = repr(
            self._thenum.quantize(1)
            if self._thenum == self._thenum.to_integral()
            else self._thenum.normalize()
        )
        return x


class _CalcStringFunction(_CalcStringBase):
    """
     _CalcStringFunction - An internal class to represent a function
    (stored as a FunctionsType with optional _CalcStringBase parameters) 
    in the _current_calc list.
    """

    def __init__(self, func: FunctionsType, param: _CalcStringBase | int) -> None:
        self._func = func
        if isinstance(param, _CalcStringBase):
            self._param = param
        else:
            # attempt to convert it to a number
            self._param = _CalcStringNumber(param)

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, _CalcStringFunction)
            and self._func == other._func
            and self._param == other._param
        )

    def get_disp(self) -> str:
        x = f"{self._func.display_func}({self._param.get_disp()})"
        return x

    def get_eval(self) -> str:
        x = f"{self._func.eval_func}({self._param.get_eval()})"
        return x


class _CalcStringString(_CalcStringBase):
    """
    _CalcStringString - An internal class to represent a string value
    (stored as a str) in the _current_calc list. String values represent
    either mathematical operators like + or *, parenthesis, default variables
    (like pi or e) or user defined variables.
    """

    def __init__(self, thestr: str) -> None:
        self._thestr = thestr

    def __eq__(self, other) -> bool:
        return isinstance(other, _CalcStringString) and self._thestr == other._thestr

    def get_disp(self) -> str:
        new_var = self._thestr
        return new_var

    def get_eval(self) -> str:
        return self._thestr


class CalculatorData:
    """CalculatorData - Data and functions used by the calculator"""

    # data used by the calculator
    _current_calc: list[_CalcStringBase] = []  # the current calculation
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

    @object_wrapper
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

        valid_symbols = [cs.value for cs in CalculatorSymbols] + [
            *DEFAULT_VARIABLES.keys()
        ]

        # double checking that variable names are str
        # default variables are defined in code so should be safe
        for v in self._user_variables.keys():
            if isinstance(v, str):
                valid_symbols.append(v)
            else:
                raise ValueError(f"User variable name is not str: {v!r}")

        valid_funcs = [cf for cf in CalculatorFunctions]

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

    @object_wrapper
    def _get_num_fnc_sym(
        self, symbol: str, func: FunctionsType
    ) -> tuple[
        _CalcStringNumber | None, _CalcStringFunction | None, _CalcStringString | None
    ]:
        """
        _get_num_fnc_sym - internal function to convert _current_input, symbol,
         and func into their _CalcStringBase representations. Used by the 
         functions that display or update _current_calc.

        Parameters
        ----------
        symbol : str
            String to be added to the end of the calculation.
        func : FunctionsType
            Dataclass containing function to be added.

        Returns
        -------
        tuple[ _CalcStringNumber | None, _CalcStringFunction | None, _CalcStringString | None ]
            The _CalcStringBase representations of the number, function and symbol
        """

        if self._current_input:
            inpt = _CalcStringNumber(
                self.get_current_input(),
                (str(self._current_input)[-1] == "."),
            )
        else:
            inpt = None

        if func and func.display_func and inpt:
            infnc = _CalcStringFunction(func, inpt)
            inpt = None
        else:
            infnc = None

        if symbol:
            sym = _CalcStringString(symbol)
        else:
            sym = None
        return inpt, infnc, sym

    @object_wrapper
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

        num, fnc, sym = self._get_num_fnc_sym(symbol, func)

        tmpcalc: list[_CalcStringBase] = [c for c in [num, fnc, sym] if c != None]

        return_value = " ".join(
            e.get_disp() for e in self._current_calc + tmpcalc
        ).strip()
        return return_value

    @object_wrapper
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

        num, fnc, sym = self._get_num_fnc_sym(symbol, func)

        tmpcalc: list[_CalcStringBase] = [c for c in [num, fnc, sym] if c != None]

        return_value = " ".join(
            e.get_eval() for e in self._current_calc + tmpcalc
        ).strip()
        return return_value

    @object_wrapper
    def get_current_input(self) -> Decimal | None:
        """
        get_current_input - Get current number input as a Decimal.

        Returns
        -------
        Decimal | None
            Decimal version of the number currently being input, None if no
            number is currently being input.
        """

        if self._current_input:
            return Decimal(self._current_input)
        else:
            return None

    @object_wrapper
    def get_user_variables(self) -> VariablesType:
        """
        get_user_variables - Return a deepcopy of _user_variables

        Returns
        -------
        VariablesType
            A deepcopy of the _user_variables
        """
        return deepcopy(self._user_variables)

    @object_wrapper
    def set_user_variables(self, user_variables: VariablesType) -> None:
        """
        set_user_variables - Set _user_variables
        """

        # this validation is duplicated from uservarseditfrm
        # but I don't want to leave the api vulnerable here
        # or lose the ability to identify the problem row there
        validate_user_vars(user_variables)

        self._user_variables = user_variables

    @object_wrapper
    def update_current_calc(
        self,
        symbol: str = "",
        func: FunctionsType = CalculatorFunctions.NOFUNCTION,
    ) -> None:
        """
        update_current_calc - Update the current calculation being input.

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

        num, fnc, sym = self._get_num_fnc_sym(symbol, func)

        tmpcalc: list[_CalcStringBase] = [c for c in [num, fnc, sym] if c != None]

        self._current_calc += tmpcalc

        self._current_input = ""

        self.update_display()

    @object_wrapper
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

    @object_wrapper
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

    @object_wrapper
    def backspace(self) -> None:
        """backspace - Erase last character from number being input."""

        # if we have a number being input, remove last digit
        if self._current_input:
            self._current_input = self._current_input[:-1]

        # if we have a function in the last place
        elif self._current_calc and isinstance(
            self._current_calc[-1], _CalcStringFunction
        ):
            last = self._current_calc[-1]._param

            # if it is a nested function or a function with a variable parameter, unnest
            if isinstance(last, _CalcStringFunction) or isinstance(
                last, _CalcStringString
            ):
                self._current_calc[-1] = last

            # if it is a single number parameter
            elif isinstance(last, _CalcStringNumber):
                self._current_input = last.get_disp().replace(",", "")
                del self._current_calc[-1]

            # unexpected parameter(s)
            else:
                self.bell()

        # if we have a string (a variable, math operator, etc), remove it
        elif self._current_calc and isinstance(
            self._current_calc[-1], _CalcStringString
        ):
            del self._current_calc[-1]

        # if we have a number, put it in _current_input and remove last digit
        elif self._current_calc and isinstance(
            self._current_calc[-1], _CalcStringNumber
        ):
            self._current_input = (
                self._current_calc[-1].get_disp().replace(",", "")[:-1]
            )
            del self._current_calc[-1]

        # if we have nothing (or unexpected list member), ring the bell
        else:
            self.bell()

        self.update_display()

    @object_wrapper
    def clear_value(self) -> None:
        """
        clear_value - Clear the current number input, or if that is empty
        then clear the current calculation.
        """

        if self._current_input:
            self._current_input = ""
        else:
            self._current_calc = []

        self.update_display()

    @object_wrapper
    def clear_all(self) -> None:
        """
        clear_all - Clear the current number being input, the current
        calculation, and the display. Does not clear the value in memory.
        """

        self.clear_display()

        self._current_calc = []
        self._current_input = ""

        self.update_display()

    @object_wrapper
    def get_memory_label(self, master) -> ttk.Label:
        """
        get_memory_label - Creates a ttk.Label tied to _memval

        Parameters
        ----------
        master : any valid tk widget that can contain a label
            The parent widget that will have this label, normally a Frame

        Returns
        -------
        ttk.Label
            The label with _memval providing data
        """
        return ttk.Label(master, textvariable=self._memval)

    @object_wrapper
    def get_current_memory(self) -> Decimal | None:
        """
        get_current_memory - Get the current value stored in memory as a Decimal.

        Returns
        -------
        Decimal | None
            Decimal version of the value stored in memory, or None if no value is
            currently stored in memory.
        """

        mem = self._memval.get().replace(",", "")
        if mem:
            return Decimal(mem)
        else:
            return None

    @object_wrapper
    def memory_clear(self) -> None:
        """memory_clear - Clear the value stored in memory"""

        self._memval.set("")

    @object_wrapper
    def memory_recall(self) -> None:
        """
        memory_recall - Replace the current number being input with the value
        stored in memory.
        """

        cur_mem = numtostr(self.get_current_memory())
        if cur_mem:
            self._current_input = cur_mem
            self.update_display()
        else:
            self.bell()

    @object_wrapper
    def memory_store(self) -> None:
        """
        memory_store - Change the value stored in memory to be the same as the
        current number being input.

        Notes
        -----
        Cannot do a simple set because we round and format the display.
        """

        # get current value
        cur_val = self.get_current_input()

        if cur_val:
            # store it
            self._memval.set(numtostr(cur_val, commas=True) or "")
        else:
            self.bell()

    @object_wrapper
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

        # get current memory
        cur_mem = numtostr(self.get_current_memory())

        if cur_mem or cur_num:
            # store memory in current value
            self._current_input = cur_mem or ""

            # store retrieved current value in memory
            self._memval.set(cur_num or "")

            self.update_display()
        else:
            self.bell()

    @object_wrapper
    def memory_add(self, addto: bool = True) -> None:
        """
        memory_add - Add or subtract the current number being input to or from
        the value stored in memory.

        Notes
        -----
        If addto is passed in as false, will subtract the value being input
        from memory by multiplying the value by -1 before adding.

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

        # get the current input number
        cur_val = self.get_current_input()
        if cur_val:

            # get current memory
            cur_mem = self.get_current_memory() or Decimal(0)

            # add (or subtract)
            mv = cur_mem + (cur_val * sign)
            self._memval.set(numtostr(mv, commas=True) or "")
        else:
            self.bell()

    @object_wrapper
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
            negateval = -(self.get_current_input() or Decimal(0))
            self._current_input = numtostr(negateval) or ""
            self.update_display()

        elif self._current_calc and (
            (
                isinstance(self._current_calc[-1], _CalcStringString)
                and (
                    self._current_calc[-1].get_disp() in DEFAULT_VARIABLES.keys()
                    or self._current_calc[-1].get_disp() in self._user_variables.keys()
                )
            )  # if we have a variable
            or (
                isinstance(self._current_calc[-1], _CalcStringFunction)
            )  # or a function
            or (isinstance(self._current_calc[-1], _CalcStringNumber))  # or a number
        ):
            inpt = self._current_calc.pop()
            self.update_current_calc(CalculatorSymbols.SUBTRACTION)
            self._current_calc.append(inpt)
            self.update_display()

        else:
            self.bell()

    @object_wrapper
    def inverse_number(self) -> None:
        """
        inverse_number - Convert the current number being input to it's
        mathematical inverse: 1/x.

        Notes
        -----
        As a side effect, will round the number currently being input to the
        precision in the Decimal context.
        """

        inpt: _CalcStringBase | None = None

        if self._current_input:
            inpt, self._current_input = _CalcStringNumber(self._current_input), ""

        elif self._current_calc and (
            (
                isinstance(self._current_calc[-1], _CalcStringString)
                and (
                    self._current_calc[-1].get_disp() in DEFAULT_VARIABLES.keys()
                    or self._current_calc[-1].get_disp() in self._user_variables.keys()
                )
            )  # if we have a variable
            or (
                isinstance(self._current_calc[-1], _CalcStringFunction)
            )  # or a function
            or (isinstance(self._current_calc[-1], _CalcStringNumber))  # or a number
        ):
            inpt = self._current_calc.pop()

        if inpt:
            self.update_current_calc(CalculatorSymbols.OPENPAREN)
            self._current_input = "1"
            self.update_current_calc(CalculatorSymbols.DIVISION)
            self._current_calc.append(inpt)
            self.update_current_calc(CalculatorSymbols.CLOSEPAREN)
        else:
            self.bell()

    @object_wrapper
    def square_number(self) -> None:
        """
        square_number - Convert the current number being input to its
        square: x**2.

        Notes
        -----
        As a side effect, will round the number currently being input to the
        precision in the Decimal context.
        """

        self.update_current_calc(CalculatorSymbols.EXPONENTIATION)
        self._current_input = "2"
        self.update_current_calc()

    @object_wrapper
    def root_number(self) -> None:
        """
        root_number - Convert the current number being input to its
        square root: Decimal.sqrt(x).

        Notes
        -----
        As a side effect, will round the number currently being input to the
        precision in the Decimal context.
        """

        # TODO: put all this logic into _get_num_fnc_sym to abstract it for future functions
        # then this just becomes a single call to update_current_calc

        # if we have a number being input
        if self._current_input:
            self.update_current_calc(func=CalculatorFunctions.SQUAREROOT)

        # if we have a variable or number or function available to wrap
        elif self._current_calc and (
            (
                isinstance(self._current_calc[-1], _CalcStringString)
                and (
                    self._current_calc[-1].get_disp() in DEFAULT_VARIABLES.keys()
                    or self._current_calc[-1].get_disp() in self._user_variables.keys()
                )
            )  # if we have a variable
            or (
                isinstance(self._current_calc[-1], _CalcStringFunction)
            )  # or a function
            or (isinstance(self._current_calc[-1], _CalcStringNumber))  # or a number
        ):
            self._current_calc[-1] = _CalcStringFunction(
                CalculatorFunctions.SQUAREROOT, self._current_calc[-1]
            )
            self.update_display()

        else:
            self.bell()

    @object_wrapper
    def calculate(self) -> None:
        """
        calculate - Performs the current calculation and updates the display
        with the results.
        """

        # update current calc and display
        self.update_current_calc()

        cur_calc = self.get_current_eval_calc()

        # if we have a calculation to perform
        if cur_calc:
            try:
                # run the current calculation
                val = evaluate_calculation(
                    cur_calc,
                    self._user_variables,
                )

                # show the result
                self.write_to_display(f" = {numtostr(val, commas=True)}\n{'=' * 30}\n")

                # clear current calc and set current input to result
                self._current_calc = []
                self._current_input = numtostr(val) or ""

            except Exception as error:
                logerror(error, "calculate", 2)

                # clear the current calculation and print the error message
                errmsg = error.__class__.__qualname__
                if errmsg == "TypeError":
                    errmsg = str(error).split(":")[0]
                elif errmsg == "SyntaxError":
                    errmsg = f"{errmsg}: {str(error)}"
                    unknown_line_1 = " (<unknown>, line 1)"
                    if errmsg.endswith(unknown_line_1):
                        errmsg = errmsg[: -(len(unknown_line_1))]
                self.write_to_display(f"=== ERROR ===\n{errmsg}\n=== ERROR ===\n")

                self._current_calc = []
                self._current_input = ""

        # update the display
        self.update_display()
