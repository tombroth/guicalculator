from copy import deepcopy

from ....globals import VariablesType
from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData


@object_wrapper
def get_user_variables(self: CalculatorData) -> VariablesType:
    """
    get_user_variables - Return a deepcopy of _user_variables

    Returns
    -------
    VariablesType
        A deepcopy of the _user_variables
    """
    return deepcopy(self._user_variables)
