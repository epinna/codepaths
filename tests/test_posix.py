#!/usr/bin/env python3

import unittest
import sys
import os

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from codepaths import Binary, CodepathsEx, _find_sinks_in_functions

class PosixTests(unittest.TestCase):


    def test_1_functions(self):
        
        b = Binary('./posix/1.c.testbin')
        
        self.assertEqual(len(b.functions), 6)

    def test_1_single_paths_between(self):
        
        b = Binary('./posix/1.c.testbin')
        result = b.paths_between('sym._func4', 'entry0')
        
        self.assertEqual(result, {
                ('sym._func4', 'entry0'): [
                    ['entry0', 'sym._func1', 'sym._func3', 'sym._func4']
                ]
        })

    def test_1_paths_between_from_the_middle(self):
        
        b = Binary('./posix/1.c.testbin')
        result = b.paths_between('sym._func4', 'sym._func1')
        
        self.assertEqual(result, {
                ('sym._func4', 'sym._func1'): [
                    ['sym._func1', 'sym._func3', 'sym._func4']
                ]
        })

    def test_1_multiple_paths_between(self):

        b = Binary('./posix/1.c.testbin')
        result = b.paths_between('sym._func5', 'entry0')
        self.assertEqual(result, {
            ('sym._func5', 'entry0'): [
                ['entry0', 'sym._func5'], 
                ['entry0', 'sym._func1', 'sym._func3', 'sym._func4', 'sym._func5']
            ]
        })

    def test_1_paths_between__w_wrong_sym(self):

        b = Binary('./posix/1.c.testbin')
        self.assertRaises(CodepathsEx, b.paths_between, 'sym.bogus', 'entry0')

    def test_2_paths_between_from_the_middle(self):
        
        b = Binary('./posix/2.c.testbin')
        result = b.paths_between('sym.imp.execvp', 'sym._func1')
        
        self.assertEqual(result, {
            ('sym.imp.execvp', 'sym._func1'): [
                ['sym._func1', 'sym._func3', 'sym._func4', 'sym.imp.execvp']
            ]
        })
        
    def test_2_find_sinks_in_functions(self):
        
        b = Binary('./posix/2.c.testbin')
        result = _find_sinks_in_functions('exec', b.functions)
        
        self.assertEqual(result, [ 'sym.imp.execvp' ])
        
        