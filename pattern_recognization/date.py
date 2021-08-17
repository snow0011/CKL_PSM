#!/usr/bin/env python3
"""
Select passwords with date patterns from input dataset 
"""
import argparse
import json
import sys
from collections import defaultdict
from typing import TextIO, Tuple, Callable, List
import re

"""
Password record for pattern recognization.
"""
class Record:
    def __init__(self, pwd:str, freq:int=1):
        self.pwd = pwd
        self.pattern = ""
        self.freq = freq

"""
Block list of date chunks. Such chunks occur in datasets frequently and are not date pattern.
"""
class BlockList:
    def __init__(self, blocks:List[str]=[]):
        self.list = self.getDefaultList()
        self.list = self.list + blocks
        self.table = set()
        for item in self.list:
            self.table.add(item)

    def isNotBlockSegment(self, pwd:str)->bool:
        if isinstance(pwd, Tuple):
            pwd = pwd[0]

        return pwd not in self.table 

    def getDefaultList(self)->List[str]:
        list = [
            "111111",
            "123123",
            "111000",
            "112233",
            "100200",
            "111222",
            "121212",
            "520520",
            "110110",
            "123000",
            "101010",
            "111333",
            "110120",
            "102030",
            "110119",
            "121314",
            "521125",
            "120120",
            "101203",
            "122333",
            "121121",
            "101101",
            "131211",
            "100100",
            "321123",
            "110112",
            "112211",
            "111112",
            "520521",
            "110111"
        ]
        return list


class PwdFilter:
    def __init__(self, block:BlockList=BlockList()):
        self.block = block
        self.total = 0
        self.filter_number = 0

    def isValid(self, pwd:Record)->bool:
        return True

    def filter(self, pwdList:List[Record])->List[Record]:
        return list(filter(lambda x : self.isValid(x), pwdList))

    def finish(self):
        print("Total password checked: %d\nFilter password number: %d\ndate pattern password: %d, %5.2f\n" % (self.total, self.filter_number, self.total-self.filter_number, (self.total-self.filter_number) / self.total * 100))

"""
Filter string which does not contain date patterns.
"""
class DatePwdFilter(PwdFilter):
    def getPwd(self, result):
        if isinstance(result, Tuple):
            return result[0]
        return result

    def isValid(self, record:Record)->bool:
        patterns_all = [
            # YYYYMMDD
            r'^((19|20)\d{2}0[123456789]0[123456789])$',
            r'^((19|20)\d{2}0[123456789][12]\d{1})$',
            r'^((19|20)\d{2}0[123456789]3[01])$',
            r'^((19|20)\d{2}1[012][0][123456789])$',
            r'^((19|20)\d{2}1[012][12]\d{1})$',
            r'^((19|20)\d{2}1[012]3[01])$',
            # MMDDYYYY
            r'^(0[123456789]0[123456789](19|20)\d{2})$',
            r'^(0[123456789][12]\d{1}(19|20)\d{2})$',
            r'^(0[123456789]3[01](19|20)\d{2})$',
            r'^(1[012][0][123456789](19|20)\d{2})$',
            r'^(1[012][12]\d{1}(19|20)\d{2})$',
            r'^(1[012]3[01](19|20)\d{2})$',
            # DDMMYYYY
            r'^(0[123456789]0[123456789](19|20)\d{2})$',
            r'^([12]\d{1}0[123456789](19|20)\d{2})$',
            r'^(3[01]0[123456789](19|20)\d{2})$',
            r'^([0][123456789]1[012](19|20)\d{2})$',
            r'^([12]\d{1}1[012](19|20)\d{2})$',
            r'^(3[01]1[012](19|20)\d{2})$',
            # YYMMDD
            r'^(19|20)0[123456789]0[123456789]$',
            r'^(19|20)0[123456789][12]\d{1}$',
            r'^(19|20)0[123456789]3[01]$',
            r'^(19|20)1[012][0][123456789]$',
            r'^(19|20)1[012][12]\d{1}$',
            r'^(19|20)1[012]3[01]$',
            # MMDDYY
            r'^0[123456789]0[123456789](19|20)$',
            r'^0[123456789][12]\d{1}(19|20)$',
            r'^0[123456789]3[01](19|20)$',
            r'^1[012][0][123456789](19|20)$',
            r'^1[012][12]\d{1}(19|20)$',
            r'^1[012]3[01](19|20)$',
            # DDMMYY
            r'^0[123456789]0[123456789](19|20)$',
            r'^[12]\d{1}0[123456789](19|20)$',
            r'^3[01]0[123456789](19|20)$',
            r'^[0][123456789]1[012](19|20)$',
            r'^[12]\d{1}1[012](19|20)$',
            r'^3[01]1[012](19|20)$',
        ]
        patterns = [
            # YYYYMMDD
            r'((19|20)\d{2}0[123456789]0[123456789])',
            r'((19|20)\d{2}0[123456789][12]\d{1})',
            r'((19|20)\d{2}0[123456789]3[01])',
            r'((19|20)\d{2}1[012][0][123456789])',
            r'((19|20)\d{2}1[012][12]\d{1})',
            r'((19|20)\d{2}1[012]3[01])',
            # MMDDYYYY
            r'(0[123456789]0[123456789](19|20)\d{2})',
            r'(0[123456789][12]\d{1}(19|20)\d{2})',
            r'(0[123456789]3[01](19|20)\d{2})',
            r'(1[012][0][123456789](19|20)\d{2})',
            r'(1[012][12]\d{1}(19|20)\d{2})',
            r'(1[012]3[01](19|20)\d{2})',
            # DDMMYYYY
            r'(0[123456789]0[123456789](19|20)\d{2})',
            r'([12]\d{1}0[123456789](19|20)\d{2})',
            r'(3[01]0[123456789](19|20)\d{2})',
            r'([0][123456789]1[012](19|20)\d{2})',
            r'([12]\d{1}1[012](19|20)\d{2})',
            r'(3[01]1[012](19|20)\d{2})',
            # YYMMDD
            r'\d{2}0[123456789]0[123456789]',
            r'\d{2}0[123456789][12]\d{1}',
            r'\d{2}0[123456789]3[01]',
            r'\d{2}1[012][0][123456789]',
            r'\d{2}1[012][12]\d{1}',
            r'\d{2}1[012]3[01]',
            # MMDDYY
            r'0[123456789]0[123456789]\d{2}',
            r'0[123456789][12]\d{1}\d{2}',
            r'0[123456789]3[01]\d{2}',
            r'1[012][0][123456789]\d{2}',
            r'1[012][12]\d{1}\d{2}',
            r'1[012]3[01]\d{2}',
            # DDMMYY
            r'0[123456789]0[123456789]\d{2}',
            r'[12]\d{1}0[123456789]\d{2}',
            r'3[01]0[123456789]\d{2}',
            r'[0][123456789]1[012]\d{2}',
            r'[12]\d{1}1[012]\d{2}',
            r'3[01]1[012]\d{2}',
        ]
        self.total = self.total + record.freq
        for pattern in patterns_all:
            s = re.fullmatch(pattern,record.pwd)
            #ss = re.match(pattern,record.pwd)
            # for s in ss:
            if s is None:
                continue
            s = s.group()
            if self.block.isNotBlockSegment(s):
                print(s, "valid",record.pwd,  pattern)
                record.pattern = self.getPwd(s)
                return True
        self.filter_number = self.filter_number + record.freq
        return False

def main():
    cli = argparse.ArgumentParser("Search all passwords match date pattern")
    cli.add_argument("-i", "--input", required=False, dest="input", default=sys.stdin, type=argparse.FileType('r'),
                     help="input password file. one password one line")
    cli.add_argument("-o", "--output", required=False, dest="output", default=sys.stdout, type=argparse.FileType("w"),
                     help="output password which match date pattern")
    cli.add_argument("--detail", required=False, action="store_true", default=False, dest="detail",
                    help="show detail information from filter")
    cli.add_argument("--freq", required=False, default=-1, dest="freq", type=int, 
                    help="frequency index. input one line with password and frequency")
    cli.add_argument("--split", required=False, dest="split", default="\t", type=str,
                     help="how to split a line in password file, default is '\\t'")
    args = cli.parse_args()
    spliter = args.split.replace('\\\\', '\\')
    if spliter == '\\t':
        spliter = '\t'
    list = []
    if args.freq <= 0:
        list = [Record(pwd.strip("\r\n").split(spliter)[0]) for pwd in args.input]
    else:
        list = [Record(pwd.strip("\r\n").split(spliter)[0], freq=int(float(pwd.strip("\r\n").split(spliter)[args.freq]))) for pwd in args.input]
    f = DatePwdFilter()
    total_pwd = sum([item.freq for item in list])
    result = f.filter(list)
    writer = args.output
    total_cnt= sum([item.freq for item in result])
    for item in result:
        if args.detail:
            writer.write(f"{item.pwd}\t{item.freq}\t{item.pattern}\n")
        else:
            writer.write(f"{item.pwd}\t{item.freq}\t{item.freq / total_pwd * 100:7.4f}\n")
    if args.detail:
        f.finish()
    print(f"containing date: {total_cnt / total_pwd * 100:5.2f}", file=sys.stderr)
    pass

if __name__ == "__main__":
    main()
