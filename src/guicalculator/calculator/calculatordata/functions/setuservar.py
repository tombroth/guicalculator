from ....globals import VariablesType
from ...logwrapper import object_wrapper
from ...validate_user_var import validate_user_vars
from ..calculatordata import CalculatorData


@object_wrapper
def set_user_variables(self: CalculatorData, user_variables: VariablesType) -> None:
    """
    set_user_variables - Set _user_variables
    """

    # this validation is duplicated from uservarseditfrm
    # but I don't want to leave the api vulnerable here
    # or lose the ability to identify the problem row there
    validate_user_vars(user_variables)

    self._user_variables = user_variables
