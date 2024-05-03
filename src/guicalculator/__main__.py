""""
__main__.py - To make the module executable.
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

import argparse
import logging
import os
import sys

from . import GuiCalculator
from .calculator import enable_gui_logging


def parse_args() -> argparse.Namespace:
    """
    parse_args - Parse command line arguments

    Returns
    -------
    argparse.Namespace
        The parsed arguments
    """

    parser = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]),
        description="A calculator written with python and tkinter",
        epilog="Copyright (c) 2024 Thomas Brotherton. See https://github.com/tombroth/guicalculator for licensing details.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    loglevels = [
        levelName.lower()
        for levelName, levelValue in logging.getLevelNamesMapping().items()
        if levelValue not in [0, 50]
    ]
    loglevels.append("none")

    parser.add_argument(
        "-l",
        "--log-level",
        type=str.lower,
        default="none",
        help="set log level",
        choices=loglevels,
    )

    parser.add_argument(
        "-o",
        "--logging-output-file",
        default=None,
        help="log file destination",
    )

    parser.add_argument(
        "-g",
        "--log-gui-calls",
        action="store_true",
        default=None,
        help="log file destination",
    )

    args = parser.parse_args()

    if args.log_gui_calls:
        enable_gui_logging()

    return args


def setup_logging(args: argparse.Namespace) -> None:
    """
    setup_logging - Configure logging

    By default, the logging decorators capture function calls at the INFO
    level, function return values at the DEBUG level, and errors at the
    ERROR level with stack trace.

    Any errors that aren't re-raised should be logged by the exception handler
    explicitly by calling logerror.

    Logging of __init__ is usually omitted.

    Parameters
    ----------
    args : argparse.Namespace
        The parsed command line arguments that contain logging options
    """

    if args.log_level == "none":
        logging.getLogger().addHandler(logging.NullHandler())
        return

    logger = logging.getLogger()

    if args.logging_output_file:
        # add an error handler for error/critical level to stderror
        errHandler = logging.StreamHandler(stream=sys.stderr)
        errHandler.setLevel(logging.ERROR)

        handlers: list[logging.Handler] = [
            logging.FileHandler(
                filename=f"{args.logging_output_file}", encoding="utf-8", mode="w"
            ),
            errHandler,
        ]
    else:
        handlers = [logging.StreamHandler(stream=sys.stdout)]

    logging.basicConfig(
        format="[%(asctime)s] [%(levelname)8s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=args.log_level.upper(),
        handlers=handlers,
    )
    logger.info(f"Logging configured at {args.log_level.upper()}")

    if args.log_gui_calls:
        logger.info(f"Including gui calls in log")
    else:
        logger.info(f"Not including gui calls in log")


# poetry build system seems to run better having a target function to run
def main():
    args = parse_args()

    setup_logging(args)

    _ = GuiCalculator()


if __name__ == "__main__":
    main()
