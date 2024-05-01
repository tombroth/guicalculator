"""
evaluate_calculation.py - Evaluate the provided calculation, returning the
    result as Decimal. This is  the parser.
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

import ast
import operator
from decimal import Decimal
from typing import Any, Callable, Type
from unicodedata import normalize

from ..globals import DEFAULT_VARIABLES, NORMALIZE_FORM, VariablesType
from .logwrapper import plain_wrapper
from .validate_user_var import validate_user_vars

# map of ast operators to functions used by parser
OPERATOR_MAP: dict[Type[ast.AST], Callable] = {
    ast.Div: operator.truediv,
    ast.Mult: operator.mul,
    ast.Sub: operator.sub,
    ast.Add: operator.add,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
    ast.Pow: operator.pow,
}


@plain_wrapper
def evaluate_calculation(
    current_calculation: str, user_variables: VariablesType
) -> Decimal:
    """
    evaluate_calculation - Evaluate the provided calculation, returning the
    result as Decimal.

    Parameters
    ----------
    current_calculation : str
        The calculation
    user_variables : VariablesType : dict[str, Decimal]
        Dictionary of user defined variables

    Returns
    -------
    Decimal
        The result of the calculation

    Raises
    ------
    TypeError
        Used for custom errors, message indicates what the specific error was.

    """

    # internal function, nested so it can't be called directly
    #
    # unnesting would remove the validation done in the outer procedure
    def _eval(node: ast.AST) -> Decimal:
        """_eval - Internal recursive function to evaluate the ast nodes"""

        # used in multiple error messages
        node_fmtd = ast.dump(node, annotate_fields=False)

        match node:
            case ast.Expression():
                return _eval(node.body)

            # replaced with Decimal numbers, left in just in case
            case ast.Constant():
                if isinstance(node.value, (int, float)):
                    return +Decimal(node.value)
                else:
                    raise TypeError(f"Unknown constant {node_fmtd}")

            case ast.BinOp():
                left, right, op = node.left, node.right, node.op
                method = OPERATOR_MAP[type(op)]
                return method(_eval(left), _eval(right))

            case ast.UnaryOp():
                operand, uop = node.operand, node.op
                method = OPERATOR_MAP[type(uop)]
                return method(_eval(operand))

            case ast.Name():

                if normalize(NORMALIZE_FORM, node.id) in DEFAULT_VARIABLES:
                    return +DEFAULT_VARIABLES[normalize(NORMALIZE_FORM, node.id)]

                elif normalize(NORMALIZE_FORM, node.id) in user_variables:
                    return +user_variables[normalize(NORMALIZE_FORM, node.id)]

                else:
                    node_escpd = node.id.encode("unicode_escape")
                    raise TypeError(f"Unknown variable {node_escpd!r}")

            case ast.Call():
                pkg, func = _get_caller(node, node_fmtd)

                # if I ever allow more function calls, will have to make another dict
                if (pkg, func) in (("decimal", "Decimal"), ("", "Decimal")):
                    parm = _get_str_parameter(node)
                    return +Decimal(parm)
                elif (pkg, func) == ("Decimal", "sqrt"):

                    return Decimal.sqrt(_eval(node.args[0]))
                else:
                    raise TypeError(f"Unknown function call {pkg}.{func}: {node_fmtd}")

            case _:
                raise TypeError(f"Unknown ast node: {node_fmtd}")

    # back to the outer function
    #
    # validate that nothing improper is in user_variables
    # we should be able to trust DEFAULT_VARIABLES
    validate_user_vars(user_variables)

    # validate we actually have a str in current_calculation
    if not current_calculation or type(current_calculation) != str:
        raise TypeError("Invalid calculation")

    root_node = ast.parse(current_calculation, mode="eval")

    val = _eval(root_node)
    return val


@plain_wrapper
def _get_str_parameter(node: ast.Call) -> str:
    """
    _get_str_parameter - Internal function to return a single str
    parameter of an ast Call.
    """

    if len(node.args) == 1 and isinstance(node.args[0], ast.Constant):
        parm = node.args[0].value
    else:
        raise TypeError("Decimal function accepts exactly one argument")
    if type(parm) == str:
        return parm
    else:
        raise TypeError("Decimal function should only have str parameter")


@plain_wrapper
def _get_caller(node: ast.Call, node_fmtd: str) -> tuple[Any, Any]:
    """
    _get_caller - Internal function to get calling module/function name.
    """

    if isinstance(node.func, ast.Attribute):  # package.procedure
        if isinstance(node.func.value, ast.Name):
            pkg = node.func.value.id
            func = node.func.attr
        else:  # ??? not sure if this can happen
            errmsg = f"Unknown type of ast.Call: {node_fmtd}"
            raise TypeError(errmsg)

    elif isinstance(node.func, ast.Name):  # procedure
        pkg = ""
        func = node.func.id

    else:  # ??? not sure if this can happen
        errmsg = f"Unknown type of ast.Call: {node_fmtd}"
        raise TypeError(errmsg)
    return pkg, func
