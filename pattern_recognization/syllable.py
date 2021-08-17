#!/usr/bin/env python3
"""
Select passwords with syllable patterns from input dataset 
"""
import argparse
import json
import sys
from collections import defaultdict
from typing import TextIO, Tuple, Callable, List
import re

class Record:
    def __init__(self, pwd:str, freq:int=1):
        self.pwd = pwd
        self.pattern = ""
        self.freq = freq

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
        list = []
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

    def finish(self, output=sys.stdout):
        output.write("Total password checked: %d\nFilter password number: %d\nmeet pattern password: %d, %5.2f\n" % (self.total, self.filter_number, self.total-self.filter_number, (self.total-self.filter_number)/ self.total * 100))

class SyllablePwdFilter(PwdFilter):
    def __init__(self, ll:List[str]):
        super().__init__()
        self.dict = list
        self.letterPettern = re.compile(r'[A-Za-z]+')
        self.checkList = list(map(lambda s : re.compile('^'+s), ll)) + list(map(lambda s : re.compile(s+'$'), ll))

    def isValid(self, pwd:Record):
        # subwords = self.letterPettern.findall(pwd.pwd)
        # for subword in subwords:
        #     for check in self.checkList:
        #         res = check.fullmatch(subword)
        #         if res is not None:
        #             pwd.pattern = res[0]+'<Syllable>'
        #             return True
        for check in self.checkList:
            res = check.fullmatch(pwd.pwd)
            if res is not None:
                pwd.pattern = res.group()+'<Syllable>'
                return True
        return False


class PinYinFilter(PwdFilter):
    def __init__(self, list:List[str]):
        super().__init__()
        self.dict = list
        list = filter(lambda x : len(x) > 1, list)
        self.letterPettern = re.compile(r'[A-Za-z]+')
        self.pinyinPettern = re.compile('^('+'|'.join(list)+')+$')

    def isValid(self, pwd:Record):
        # subwords = self.letterPettern.findall(pwd.pwd)
        # for subword in subwords:
        #     res = self.pinyinPettern.match(subword)
        #     if res is not None:
        #         pwd.pattern = res[0]+'<PinYin>'
        #         return True
        res = self.pinyinPettern.fullmatch(pwd.pwd)
        if res is None:
            return False
        pwd.pattern = res.group() + '<PinYin>'
        return True

class CombinationPwdFilter(PwdFilter):
    def __init__(self, list:List[PwdFilter]):
        super().__init__()
        self.list = list

    def isValid(self, pwd):
        self.total += pwd.freq
        for checker in self.list:
            if checker.isValid(pwd):
                return True
        self.filter_number += pwd.freq
        return False

def main():
    cli = argparse.ArgumentParser("Search all passwords match syllable pattern")
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
    cli.add_argument("--syllable", required=False, dest="syllable", default=None, type=argparse.FileType('r'),
                     help="Syllable file to recognize.")
    cli.add_argument("--pinyin", required=False, dest="pinyin", default=None, type=argparse.FileType('r'),
                     help="Pinyin file to recognize")
    args = cli.parse_args()
    spliter = args.split.replace('\\\\', '\\')
    if spliter == '\\t':
        spliter = '\t'
    list = []
    if args.freq <= 0:
        list = [Record(pwd.strip("\r\n").split(spliter)[0]) for pwd in args.input]
    else:
        list = [Record(pwd.strip("\r\n").split(spliter)[0], freq=int(float(pwd.strip("\r\n").split(spliter)[args.freq]))) for pwd in args.input]
    if args.syllable is None:
        syllables = []
    else:
        syllables = [line.strip('\r\n') for line in args.syllable]
    if args.pinyin is None:
        pinyins = []
    else:
        pinyins = [line.strip('\r\n') for line in args.pinyin]
    f = CombinationPwdFilter([PinYinFilter(pinyins), SyllablePwdFilter(syllables)])
    result = f.filter(list)
    total_chunk = sum([item.freq for item in result])
    total_pwd = sum([item.freq for item in list])
    rate = total_chunk / total_pwd * 100
    writer = args.output
    writer.write(f"{total_chunk} / {total_pwd} = {rate:7.4f}\n")
    if args.detail:
        f.finish(writer)
    for item in result:
        if args.detail:
            writer.write(f"{item.pwd}\t{item.freq}\t{item.pattern}\n")
        else:
            writer.write(f"{item.pwd}\t{item.freq}\n")
    pass

if __name__ == "__main__":
    main()
