"""test_logwrapper.py - Test script for the logwrapper module."""

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
import unittest

from guicalculator.calculator import logwrapper as lw


class LogwrapperTest(unittest.TestCase):

    def test_enable_gui_logging(self):
        self.assertFalse(lw.log_gui_calls)
        lw.enable_gui_logging()
        self.assertTrue(lw.log_gui_calls)

    def test_gui_object_wrapper_logging(self):
        """Test the gui_object_wrapper function with log_gui_calls = True"""

        @lw.gui_object_wrapper
        def fnc():
            raise ValueError("Testing raising an error")

        with self.assertRaises(ValueError):
            with self.assertLogs(level=logging.ERROR) as logmsgs:
                lw.log_gui_calls = True
                fnc()
                self.assertTrue(
                    any(
                        "Testing raising an error" in errmsg
                        for errmsg in logmsgs.output
                    )
                )

    def test_gui_object_wrapper_nologging(self):
        """Test the gui_object_wrapper function with log_gui_calls = False"""

        @lw.gui_object_wrapper
        def fnc():
            raise ValueError("Testing raising an error")

        with self.assertRaises(ValueError):
            with self.assertLogs(level=logging.ERROR) as logmsgs:
                lw.log_gui_calls = False
                fnc()
                self.assertFalse(
                    any(
                        "Testing raising an error" in errmsg
                        for errmsg in logmsgs.output
                    )
                )

    def test_object_wrapper(self):
        """Test the object_wrapper function"""

        @lw.object_wrapper
        def fnc():
            raise ValueError("Testing raising an error")

        with self.assertRaises(ValueError):
            with self.assertLogs(level=logging.ERROR) as logmsgs:
                fnc()
                self.assertTrue(
                    any(
                        "Testing raising an error" in errmsg
                        for errmsg in logmsgs.output
                    )
                )

    def test_plain_wrapper(self):
        """Test the plain_wrapper function"""

        @lw.plain_wrapper
        def fnc():
            raise ValueError("Testing raising an error")

        with self.assertRaises(ValueError):
            with self.assertLogs(level=logging.ERROR) as logmsgs:
                fnc()
                self.assertTrue(
                    any(
                        "Testing raising an error" in errmsg
                        for errmsg in logmsgs.output
                    )
                )

    def test_get_signature(self):
        """Test the _get_signature function"""

        result = lw._get_signature(
            (1, "two", [3, 4, 5]), {"six": 6, "seven": 7, "eight": 8}
        )
        self.assertEqual("1, 'two', [3, 4, 5], six=6, seven=7, eight=8", result)

    def test_log_func_call(self):
        """Test the _log_func_call function"""

        def func(x: int):
            return 1 + x

        signature = "2"

        with self.assertLogs(level=logging.DEBUG) as logmsgs:
            result = lw._log_func_call(func, args=(2,), kwargs={}, signature=signature)

            self.assertTrue(
                any(
                    f"calling {func.__qualname__}, args=({signature})" in errmsg
                    for errmsg in logmsgs.output
                )
            )

            self.assertTrue(
                any(
                    f"function {func.__qualname__} returned {result!r}" in errmsg
                    for errmsg in logmsgs.output
                )
            )

            self.assertEqual(3, result)

    def test_logerror(self):
        """Test the logerror function"""

        e = ValueError("Testing raising an error")
        funcname = "funcname"

        with self.assertLogs(level=logging.ERROR) as logmsgs:
            lw.logerror(e, funcname)
            self.assertTrue(
                any(
                    f"Exception raised in {funcname}. exception: {str(e)}" in errmsg
                    for errmsg in logmsgs.output
                )
            )
