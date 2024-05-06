from abc import ABC, abstractmethod
from decimal import Decimal

from ....globals import FunctionsType


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
        return f"<{self.__class__.__qualname__} : {self.get_disp()}>"

    def __repr__(self) -> str:
        return f"<{self.__class__.__qualname__} : {self.get_eval()}>"


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
        elif isinstance(thenum, (int, float)):
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
            self._thenum.to_integral_value()
            if self._thenum == self._thenum.to_integral_value()
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
        if isinstance(self._param, _CalcStringFunction):
            x = f"({self._func.display_func}{self._param.get_disp()})"
        else:
            x = f"({self._func.display_func}({self._param.get_disp()}))"
        return x

    def get_eval(self) -> str:
        if isinstance(self._param, _CalcStringFunction):
            x = f"({self._func.eval_func}{self._param.get_eval()}{self._func.post_param_eval})"
        elif self._func.eval_func:
            x = f"({self._func.eval_func}({self._param.get_eval()}{self._func.post_param_eval}))"
        else:
            x = f"({self._param.get_eval()}{self._func.post_param_eval})"
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
