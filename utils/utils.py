#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import math
import subprocess

##################################################
# utils
def runCmd(cmd, showCmd =True, mustOk=False, showResult=False):
    '''
    run a shell command on PC and return the output result
    parameter:
        cmd --- the command line
        showCmd -- whether show running command
        mustOk -- if this option is True and command run failed, then raise a exception
        showResult -- show result of command
    '''
    if showCmd:
        print (cmd)
    ## run it ''
    result = ""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    ## But do not wait till netstat finish, start displaying output immediately ##
    while True:
        try:
            output = p.stdout.readline().decode()
        except UnicodeDecodeError as e:
            print(' UnicodeDecodeError ', e);
        if output == '' and p.poll() is not None:
            break
        if output:
            result+=str(output)
            if showResult:
                print(output.strip())
                sys.stdout.flush()
    stderr = p.communicate()[1]
    if stderr:
        print (f'STDERR:{stderr}')
    p_status = p.wait()
    if mustOk:
        if p_status is p_status !=0: raise Exception('run %s failed %d' %(cmd, p_status))
    return result

def getAlignNum(addr, align=0x10, shrink=False):
    if shrink:
        addr1 = int( math.floor(addr/align) *align)
        return addr1
    else:
        addr1 = int( math.ceil(addr/align) *align)
        return addr1



