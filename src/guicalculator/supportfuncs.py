import ast
import operator
from decimal import Decimal
from typing import Callable, Type
from unicodedata import normalize

from . import DEFAULT_VARIABLES

# map of ast operators to functions used by parser
OPERATOR_MAP: dict[Type[ast.AST], Callable] = {
    ast.Div: operator.truediv,
    ast.Mult: operator.mul,
    ast.Sub: operator.sub,
    ast.Add: operator.add,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def numtostr(
    val: int | float | Decimal,
    commas: bool = False,
    removeZeroes: bool = True,
) -> str:
    """
    numtostr - Convert number to string.

    Converts an int or float or Decimal to a string representation. Can
    add thousand separators and/or remove trailing zeroes after a decimal
    point.

    Notes
    -----
    As a side effect, will round the number currently being input to the
    precision in the Decimal context if removeZeroes is True.

    Parameters
    ----------
    val : int | float | Decimal
        Number to be converted
    commas : bool, optional
        True means add thosands separators (commas). By default False.
    removeZeroes : bool, optional
        True means remove trailing zeroes after the decimal point.
        By default True.

    Returns
    -------
    str
        The string representation of the number
    """
    v: int | float | Decimal
    if commas:
        c = ","
    else:
        c = ""

    if isinstance(val, Decimal):
        if val == val.to_integral_value() and removeZeroes:
            v = val.to_integral_value()
        else:
            if removeZeroes:
                v = (
                    val.quantize(Decimal(1))
                    if val == val.to_integral()
                    else val.normalize()
                )
            else:
                v = val
        fmt = "{0:" + c + "f}"
    elif val == int(val) and removeZeroes:
        v = int(val)
        fmt = "{0:" + c + "d}"
    else:
        v = val
        fmt = "{0:" + c + ".28g}"

    return fmt.format(v)


def strtodecimal(val: str) -> Decimal:
    """
    strtodecimal  - convert string value to Decimal.

    Parameters
    ----------
    val : str
        Value to be converted

    Returns
    -------
    Decimal
        Converted value
    """
    if val:
        return Decimal(val.replace(",", ""))
    else:
        return Decimal(0)


def evaluate_calculation(
    current_calculation: str, user_variables: dict[str, Decimal]
) -> Decimal:
    """
    evaluate_calculation - Evaluate the provided calculation, returning the
    result as Decimal.

    Parameters
    ----------
    current_calculation : str
        The calculation
    user_variables : dict[str, Decimal]
        List of user defined variables

    Returns
    -------
    Decimal
        The result of the calculation

    Raises
    ------
    TypeError
        Used for custom errors, message indicates what the specific error was.

    """

    def _eval(node: ast.AST) -> Decimal:
        """
        _eval - internal recursive function to evaluate the ast nodes

        Parameters
        ----------
        node : ast.AST
            ast node

        Returns
        -------
        Decimal
            result of evaluation

        Raises
        ------
        TypeError
            Used for custom errors, message indicates what the specific
            error was.
        """

        match node:
            case ast.Expression():
                return _eval(node.body)

            # replaced with Decimal numbers, left in just in case something
            # falls through
            case ast.Constant():
                # unary plus forces rounding to precision in Decimal context
                if isinstance(node.value, (int, float)):
                    return +Decimal(node.value)
                else:
                    node_fmtd = ast.dump(node, indent=2)
                    raise TypeError(f"Unknown constant: ast.{node_fmtd}")

            case ast.BinOp():
                left, right, op = node.left, node.right, node.op
                method = OPERATOR_MAP[type(op)]
                return method(
                    _eval(left),
                    _eval(right),
                )

            case ast.UnaryOp():
                operand, uop = node.operand, node.op
                method = OPERATOR_MAP[type(uop)]
                return method(_eval(operand))

            case ast.Name():

                # unary plus forces rounding to precision in Decimal context
                if normalize("NFKC", node.id) in DEFAULT_VARIABLES:
                    if type(DEFAULT_VARIABLES[normalize("NFKC", node.id)]) == Decimal:
                        return +DEFAULT_VARIABLES[normalize("NFKC", node.id)]
                    else:
                        raise TypeError(
                            f"Invalid data in DEFAULT_VARIABLES[{normalize('NFKC', node.id)}]"
                        )

                elif normalize("NFKC", node.id) in user_variables:
                    if type(user_variables[normalize("NFKC", node.id)]) == Decimal:
                        return +user_variables[normalize("NFKC", node.id)]
                    else:
                        raise TypeError(
                            f"Invalid data in user_variables[{normalize('NFKC', node.id)}]"
                        )

                else:
                    node_escpd = node.id.encode("unicode_escape")
                    raise TypeError(f"Unknown variable: {node_escpd!r}")

            case ast.Call():
                # if I ever allow more function calls, will have to make another dict

                if isinstance(node.func, ast.Attribute):  # package.procedure
                    if isinstance(node.func.value, ast.Name):
                        pkg = node.func.value.id
                        func = node.func.attr
                    else:  # ??? not sure if this can happen
                        node_fmtd = ast.dump(node, indent=2)
                        errmsg = f"Unknown type of ast.Call: \nast.{node_fmtd}"
                        raise TypeError(errmsg)

                elif isinstance(node.func, ast.Name):  # procedure
                    pkg = ""
                    func = node.func.id

                else:  # ??? not sure if this can happen
                    node_fmtd = ast.dump(node, indent=2)
                    errmsg = f"Unknown type of ast.Call: \nast.{node_fmtd}"
                    raise TypeError(errmsg)

                if (pkg == "decimal" and func == "Decimal") or (
                    pkg == "" and func == "Decimal"
                ):
                    # get parameter
                    if len(node.args) == 1 and isinstance(node.args[0], ast.Constant):
                        parm = node.args[0].value
                    else:
                        errmsg = "Decimal function accepts exactly one argument"
                        raise TypeError(errmsg)
                    # unary plus forces rounding to precision in Decimal context
                    return +Decimal(parm)

                else:
                    node_fmtd = ast.dump(node, indent=2)
                    raise TypeError(f"Unknown function call: \nast.{node_fmtd}")
            
            case _:
                node_fmtd = ast.dump(node, indent=2)
                raise TypeError(f"Unknown ast node: \nast.{node_fmtd}")

    root_node = ast.parse(current_calculation, mode="eval")
    val = _eval(root_node)
    return val
