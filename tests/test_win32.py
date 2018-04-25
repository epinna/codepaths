#!/usr/bin/env python3

import unittest
import sys
import os

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from codepaths import Binary, CodepathsEx, _find_sinks_in_functions

class WinTests(unittest.TestCase):

    def test_ru_find_sinks_in_functions(self):

        b = Binary('./win32/ru.exe.testbin')
        
        result = _find_sinks_in_functions('exec', b.functions)
        
        self.assertEqual(result, [ 'sub.KERNEL32.dll_GetModuleHandleW_760' ])
        
    def test_livekd64_find_sinks_in_functions(self):

        b = Binary('./win32/livekd64.exe.testbin')
        
        result = _find_sinks_in_functions('exec', b.functions)
        self.assertEqual(result, ['sub.KERNEL32.dll_GetModuleHandleA_680', 'sub.KERNEL32.dll_CreateProcessW_610', 'sub.KERNEL32.dll_GetModuleHandleA_550', 'sub.KERNEL32.dll_GetModuleHandleA_890'])
        