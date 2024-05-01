"""
logwrapper.py - Wrapper function to handle basic logging.
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

import logging
from functools import wraps
from typing import Any, Callable

logger = logging.getLogger()


def object_wrapper(func: Callable) -> Callable:
    """
    object_wrapper - wrapper that logs data for methods of objects

    Main difference from plain_wrapper is that this version excludes
    the first "self" argument.

    Parameters
    ----------
    func : Callable
        object method to wrap

    Returns
    -------
    Callable
        wrapped method
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        signature = _get_signature(args[1:], kwargs)
        return _log_func_call(func, args, kwargs, signature)

    return wrapper


def plain_wrapper(func: Callable) -> Callable:
    """
    plain_wrapper wrapper that logs data for functions

    Main difference from object_wrapper is that this version
    does not exclude the first argument.


    Parameters
    ----------
    func : Callable
        function to wrap

    Returns
    -------
    Callable
        wrapped function
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        signature = _get_signature(args, kwargs)
        return _log_func_call(func, args, kwargs, signature)

    return wrapper


def _get_signature(args: tuple, kwargs: dict[str, Any]) -> str:
    """
    _get_signature - return the function parameters for logging

    Parameters
    ----------
    args : tuple
        positional arguments
    kwargs : dict[str, Any]
        keyword arguments

    Returns
    -------
    str
        parameters passed to function as str
    """

    args_repr = [repr(a) for a in args]
    kwargs_repr = [f"{k}={v!r}" for k, v in kwargs.items()]
    signature = ", ".join(args_repr + kwargs_repr)
    return signature


def _log_func_call(
    func: Callable, args: tuple, kwargs: dict[str, Any], signature: str
) -> Any:
    """
    _log_func_call

    _extended_summary_

    Parameters
    ----------
    func : Callable
        The function to call
    args : tuple
        positional arguments
    kwargs : dict[str, Any]
        keyword arguments
    signature : str
        function parameters as returned by _get_signature

    Returns
    -------
    Any
        Whatever the function returned

    Raises
    ------
    e
        Whatever error the function raises
    """

    logger.info(f"calling {func.__qualname__}, args=({signature})", stacklevel=3)

    try:
        result = func(*args, **kwargs)
        logger.debug(f"function {func.__qualname__} returned {result!r}", stacklevel=3)
        return result

    except Exception as e:
        logerror(e, func.__qualname__, 4)
        raise e


def logerror(e: Exception, funcname: str, sl: int = 1):
    logger.exception(
        f"Exception raised in {funcname}. exception: {str(e)}",
        stacklevel=sl,
    )
