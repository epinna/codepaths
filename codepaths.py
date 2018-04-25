#!/usr/bin/env python3
import r2pipe
import time
import argparse
import sys
import re
import textwrap

DEPTH_LIMIT = 10000

SINKS = {
    'exec' : [
        # system
        'sym.imp.system(_[a-zA-Z0-9]+)?',
        # execv, execvp,  execvpe, execl, execlp, execlpe
        'sym.imp.exec[vl]p?e?(_[a-zA-Z0-9]+)?',
        # dlopen
        'sym.imp.dlopen(_[a-zA-Z0-9]+)?',
        # LoadLibraryEx
        'sub.KERNEL32.dll_LoadLibraryEx[AW]?(_[a-zA-Z0-9]+)?',
        # GetModuleHandle
        'sub.KERNEL32.dll_GetModuleHandle[AW]?(_[a-zA-Z0-9]+)?',
        # CreateProcess
        'sub.KERNEL32.dll_CreateProcess[AW]?(_[a-zA-Z0-9]+)?',
        # ShellExecuteEx
        'sub.SHELL32.dll_ShellExecuteEx[AW]?(_[a-zA-Z0-9]+)?',
        # ShellExecute
        'sub.SHELL32.dll_ShellExecuteEx[AW]?(_[a-zA-Z0-9]+)?',
        
    ]
}

class bcolors:
    RED = '\033[91m'
    ENDC = '\033[0m'

class CodepathsParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('[!] Error: %s\n\n' % message)
        self.print_help()
        sys.exit(2)

class CodepathsEx(Exception):
    pass

class Binary:
    
    def __init__(self, binpath):
        
        self.functions = {}
        self.paths = {}
        self.limit = 10000
        
        self.r2pipe = r2pipe.open(binpath)
        self._analyze()
        self._load_functions()
    
    def _analyze(self):
        self.r2pipe.cmd('aaa')
    
    def _load_functions(self):
        
        for f in self.r2pipe.cmdj('aflj'):
            if f['type'] in ('fcn', 'sym'):
                
                if not 'offset' in f or not 'name' in f:
                    raise CodepathsEx('Unexpected function data from radare: %s' % (f))
                
                self.functions[f['name']] = { 
                    'addr': hex(f['offset']) 
                }

    def _name_function(self, name_or_address):
        
        if name_or_address.startswith('0x'):
            
            for fname, fdata in self.functions.items():
                
                if name_or_address == fdata['addr']:
                    return fname
                
            # If address hasn't been found
            raise CodepathsEx('Binary does not contain functions starting at %s' % (name_or_address))
        else:
            if name_or_address in self.functions.keys():
                return name_or_address
            else:
                raise CodepathsEx('Binary does not contain function %s' % (name_or_address))
        
    def close(self):
        self.r2pipe.quit()

    def paths_between(self, start, end):
        
        start = self._name_function(start)
        end = self._name_function(end)
        
        partial_paths = [[start]]
        
        if not (start, end) in self.paths.keys():
            self.paths[(start, end)] = []
		
        # Loop while there are still unresolve paths and while all path sizes have not exceeded DEPTH_LIMIT
        while partial_paths and len(self.paths[(start, end)]) < self.limit and len(partial_paths) < self.limit:
            
            # Initialize a unique set of callers for this iteration
            callers = set()
   
            # Callee is the last entry of the first path in partial paths.
            # The first path list will change as paths are completed and popped from the list.
            callee = partial_paths[0][-1]
   
            # Find all unique functions that reference the callee, assuming this path has not
            # exceeded DEPTH_LIMIT.
            if len(partial_paths[0]) < self.limit:
                
                calls_list = self.r2pipe.cmdj("axtj @ %s" % callee)
                
                if not calls_list:
                    # No answer, assume it's the latest
                    callers.add(None)
                
                self.functions[callee]['axtj'] = calls_list
                
                for caller in calls_list:
                    
                    if not 'fcn_name' in caller:
                        callers.add(None)
                    elif caller['fcn_name'] not in callers:
                        callers.add(caller['fcn_name'])

            # If there are callers to the callee, remove the callee's current path
            # and insert new ones with the new callers appended.
            if callers:

                base_path = partial_paths.pop(0)

                for caller in callers:

                    # Don't want to loop back on ourselves in the same path
                    if caller in base_path:
                        continue

                    # If we've reached the desired end node, don't go any further down this path
                    if caller in (end, None, 'entry0'):
                        path_to_add = (base_path + [caller])[::-1]
                        if not path_to_add in self.paths[(start, end)]:
                            self.paths[(start, end)].append(path_to_add)
                    else:
                        partial_paths.append(base_path + [caller])

            # Else, our end node is not in this path, so don't include it in the finished path list.
            elif end not in partial_paths[0]:
                partial_paths.pop(0)
            # If there were no callers then this path has been exhaused and should be
            # popped from the partial path list into the finished path list.
            elif end in partial_paths[0]:
                # Paths start with the end function and end with the start function; reverse it.
                path_to_add = partial_paths.pop(0)[::-1]
                if not path_to_add in self.paths[(start, end)]:
                    self.paths[(start, end)].append(path_to_add)

        return self.paths

def _find_sinks_in_functions(catalog, binary_functions):

    # Compile all the re sinks in the catalog
    sinks_re = []
    for sink_re in SINKS.get(catalog, []):
        sinks_re.append(re.compile(sink_re))
    
    # Found all the functions in the binary which match
    # the sink catalog
    found_sinks = []
    for fname in binary_functions:
        for sink_re in sinks_re:
            if sink_re.match(fname):
                found_sinks.append(fname)
                break
                
    return found_sinks

def print_sink_paths(sources, catalog):
    
    if not sources:
        sources = [ 'entry0' ]
    
    print('[+] Analyzing all referenced code with radare2')
    
    binary = Binary(args.binpath)
    
    found_sinks = _find_sinks_in_functions(catalog, binary.functions)

    if found_sinks:
        print_paths(sources, found_sinks, binary)
    else:
        raise CodepathsEx("Can't find any call to %s functions in the binary. List all functions with 'list-func'." % catalog)
            

def print_paths(sources, sinks, binary = None):
    
    if not sources:
        sources = [ 'entry0' ]

    if not binary:        
        print('[+] Analyzing all referenced code with radare2..')
        binary = Binary(args.binpath)

    print('[+] Finding paths betwen %i sources and %i sinks..' % (len(sources), len(sinks)))

    for sink in sinks:
        for source in sources:
            paths = binary.paths_between(sink, source)
            
            for start_end, paths_list in paths.items():
                                
                for flist_i, function_list in enumerate(paths_list):
                    
                    print('\n[+] Path %d of %d between %s and %s\n' % (flist_i+1, len(paths_list), start_end[0], start_end[1]))

                    for function_i, function in enumerate(function_list):

                        called_func = None
                        if function_i < len(function_list) - 1:
                             called_func = function_list[function_i + 1]

                        if function:
                            func_name = function
                            func_addr = binary.functions[function]['addr'] + ' '
                        else:
                            func_name = '(no func)'
                            func_addr = ''

                        print(
                            '▶ %s%s%s%s' % (
                                func_addr,
                                bcolors.RED,
                                func_name, 
                                bcolors.ENDC)
                            )
                                
                        if called_func and 'axtj' in binary.functions[called_func]:
                            for reference in binary.functions[called_func]['axtj']:
                                print('| %s %s' % (hex(reference['from']), reference['opcode'] ))
                                         

    binary.close()


def print_functions():
    
    print('[+] Analyzing all referenced code with radare2')
    
    binary = Binary(args.binpath)
    if not binary.functions:
        raise CodepathsEx("Can't find any function in the binary.")
        
    for fname, fdata in binary.functions.items():
        print("%s %s" % (fdata['addr'], fname))
        
    binary.close()

def print_sinks(catalog):
    
    print('[+] Analyzing all referenced code with radare2')

    binary = Binary(args.binpath)

    if not binary.functions:
        raise CodepathsEx("Can't find any function in the binary.")
    
    found_sinks = _find_sinks_in_functions(catalog, binary.functions)
    
    if not found_sinks:
        raise CodepathsEx("Can't find any call to execution functions in the binary. List all functions with 'list-func'.")
    
    for sink_name in found_sinks:
        print("%s %s" % (binary.functions[sink_name]['addr'], sink_name))
    
    binary.close()


if __name__ == "__main__":
    
    parser = CodepathsParser()

    subparsers = parser.add_subparsers(dest='subparser', help="Find paths, list functions and sinks")

    parser_fromto = subparsers.add_parser('from-to')
    parser_fromto.add_argument("--from", dest='sources', help="list of sources functions", nargs="+")
    parser_fromto.add_argument("--to", dest='sinks', help="list of sinks functions", nargs="+")

    to_exec = subparsers.add_parser('to-exec')
    to_exec.add_argument("--from", dest='sources', help="list of sources functions", nargs="+")

    parser_funct = subparsers.add_parser('list-func')
    parser_sinks = subparsers.add_parser('list-exec')
    parser.add_argument("binpath", help="Binary path")

    args = parser.parse_args()
    
    try:
        if args.subparser == 'list-func':
            print_functions()
        elif args.subparser == 'list-exec':
            print_sinks('exec')
        elif args.subparser == 'to-exec':
            print_sink_paths(args.sources, 'exec')
        elif args.subparser == 'from-to':
            
            if not args.sinks:
                print('[+] Use from-to --to <funcX>.. [ --from <funcY>.. ]')
            else:
                print_paths(args.sources, args.sinks)
        else:
            parser.print_help()
            
    except CodepathsEx as e:
        print('[!] %s' % (e))
    except KeyboardInterrupt as e:
        print('[!] Exiting' )
        
        
