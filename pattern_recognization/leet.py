#!/usr/bin/env python3


#########################################################################
# Tries to detect Multi-words in the training dataset
#
# Aka CorrectBatteryStaple = Correct Battery Staple
#
# There's multiple ways to do this.
# For example https://github.com/s3inlc/CorrectStaple
#
# The current method attempts to learn multiwords from the training set
# directly, with a small list of assist multi words to aid in this.
#
# Aka if 'cat' and 'dog' is seen multiple times in the training set
# but 'catdog' is only seen once, attempt to break it into a multi-word
#
#########################################################################


# Attempts to identify and split up multiwords
#
# Current works by creating a base word list from the training data of
# words that occur multiple times. Once this base set is genreated will
# then attempt to break up low occurence words into smaller base words
#
import argparse
import collections
import copy
import functools
import os
import pickle
import re
import traceback
from math import floor, ceil
from typing import List, TextIO, Dict, Set, Tuple

import itertools
import sys

"""
Note that catdog will not be treated as (cat, dog) 
because both of them of length less than 4.

helloabc will be treated as (hello, abc) 
because one of multiword should be of length larger than of equal to 4
"""


def split_ado(string):
    """
    a replacement for re
    :param string: any string
    :return: alpha, digit, other parts in a list
    """
    prev_chr_type = None
    acc = ""
    parts = []
    for c in string:
        if c.isalpha():
            cur_chr_type = "alpha"
        elif c.isdigit():
            cur_chr_type = "digit"
        else:
            cur_chr_type = "other"
        if prev_chr_type is None:
            acc = c
        elif prev_chr_type == cur_chr_type:
            acc += c
        else:
            parts.append(acc)
            acc = c
        prev_chr_type = cur_chr_type
    parts.append(acc)
    return parts


def get_mask(seg):
    """
    get corresponding upper/lower tag of given seg
    Hello -> ULLLL
    :param seg:
    :return:
    """
    mask = ""
    for e in seg:
        if e.isupper():
            mask += "U"
        elif e.islower():
            mask += "L"
        else:
            mask += "L"
    return mask


def get_ado(word: str):
    """
    split word according to A, D, O tag
    hello123world -> [(hello, A, 5), (123, D, 3), (world, A, 5)]
    :param word:
    :return:
    """
    prev_chr_type = None
    acc = ""
    parts = []
    for c in word:
        if c.isalpha():
            cur_chr_type = "A"
        elif c.isdigit():
            cur_chr_type = "D"
        else:
            cur_chr_type = "O"
        if prev_chr_type is None:
            acc = c
        elif prev_chr_type == cur_chr_type:
            acc += c
        else:
            parts.append((acc, prev_chr_type, len(acc)))
            acc = c
        prev_chr_type = cur_chr_type
    parts.append((acc, prev_chr_type, len(acc)))
    return parts


class MyMultiWordDetector:

    # Initialize the Multi-word detector
    #
    # threshold = the minimum number of times that a word can be seen to be
    # classified as a base word
    #
    # min_len = miminum length for a base word from the training set.
    #           Don't want to have one letter matches or everything will be a
    #           multi-word. Note, there is a seperate list of high value base
    #           words such as 'love' and 'cat', that may be below the min_len
    #
    # max_len = maximum lenght of a multi-word to parse. This is to prevent
    #           getting hung up on 500 character passwords.
    #
    def __init__(self, threshold=5, min_len=4, max_len=21):
        self.threshold = threshold
        self.min_len = min_len
        self.max_len = max_len

        # No sense checking an input word if it is too small to be made up of
        # two base words
        #
        # Saving this value to reduce multiplications later on since this
        # will need to be checked to parse input passwords
        self.min_check_len = min_len * 2

        # This is the lookup table where base words are saved
        #
        # Rather than save all the words directly with counts, it saves a nested
        # dictionary with each level being a character. That way when parsing
        # a multiword we can walk down it trying to find matches
        #
        self.dtree = {"#1": 5}
        self.__min_len_dtree = {}
        self.lendict = {}

        # Trains on an input passwords

    #
    # One "weird" note about the lookup table. To speed things up, I'm not
    # checking mimimum length of strings before I insert them into the lookup
    # table. Therefore there will almost certainly be one, two character strings
    # in the lookup table that aren't valid base words. That's ok though since
    # their "count" wont' be recorded so they will not be treated as valid
    # base words, and since they are short and most will be parts of other
    # words, they shouldn't take up a lot of space
    #
    def train(self, input_password):

        # Quick bail out if the input password is too short or too long
        if len(input_password) < self.min_len:
            return

        if len(input_password) > self.max_len:
            return
        # Lowercase the password since multiword training is not being done
        # on capitalization or CamelCase
        password = input_password.lower()
        parts = split_ado(password)
        for part in parts:
            if len(part) < self.min_len:
                if part not in self.__min_len_dtree:
                    self.__min_len_dtree[part] = 0
                self.__min_len_dtree[part] += 1
                continue
            if part not in self.dtree:
                self.dtree[part] = 0
            self.dtree[part] += 1

    def train_file(self, password_list: TextIO):
        password_list.seek(0)
        for pwd in password_list:
            pwd = pwd.strip("\r\n")
            self.train(pwd)
        self.new_lendict()
        password_list.seek(0)
        pass

    # Gets the number of times the alpha_string has been seen in training
    #
    # alpha_string: Note making this explicit that only alpha strings should
    #               be passed in. The goal of this function is *not* to parse
    #               out digits, special characters, etc
    #
    # Returns:
    #     Int: The number of times the string was seen during training
    #
    def _get_count(self, alpha_string):
        return self.dtree.get(alpha_string.lower(), 0)

    def get_count(self, string):
        return self.dtree.get(string.lower(), 0)

    # Recusivly attempts to identify multiword parsing
    #
    # Returns
    #    None: If no parsing could be found
    #    [base1, base2, ...] if parsing was found
    #
    # Starts with the minimum len base word it can find, and then calls itself
    # recursivly with the rest of the password until one does not return None.
    # Returns None if no match can be made.

    #
    def _identify_multi(self, alpha_string):

        # Stop looking for multiwords if there is not enough letters left
        # to create a second base word
        #
        max_index = len(alpha_string) - self.min_len

        # Tries to create the largest base word possible
        #
        # Subtract 1 to min_len so that we continue through the minimum length
        for index in range(max_index, self.min_len - 1, -1):

            # If this is a valid base word
            if self._get_count(alpha_string[0:index]) >= self.threshold:

                # Check to see if the remainder is a valid base word
                if self._get_count(alpha_string[index:]) >= self.threshold:
                    # It was, so return the two items as a list
                    return [alpha_string[0:index], alpha_string[index:]]

                # Need to recursivly look for a multiword in the remainder
                results = self._identify_multi(alpha_string[index:])

                # If results indicate a parsing for the end of the alpha_string
                # It was a successful multi_word so return it as a list
                if results:
                    results.insert(0, alpha_string[0:index])
                    return results

        # Could not parse out multi-words
        return None

    def __calc_prob(self, container: List):
        prob = 1
        for part in container:
            if len(part) < self.min_len:
                continue
            prob *= self.lendict.get(len(part), {}).get(part, .0)
            if prob < 1e-50:
                break
        return container, prob / len(container)

    def _augmented_identify_multi(self, alpha_string, multi_list: List, container: List, target_len: int,
                                  threshold: int = 0):
        # Tries to create the largest base word possible
        #
        # Subtract 1 to min_len so that we continue through the minimum length
        for index in range(1, len(alpha_string), 1):
            multi_container = container
            left = alpha_string[0:index]
            left_count = self._get_count(left)
            right = alpha_string[index:]
            right_count = self._get_count(right)
            # If this is a valid base word
            if left_count + right_count > threshold:
                multi_container.append(left)
                # Check to see if the remainder is a valid base word
                # It was, so return the two items as a list
                multi_container.append(right)
                if len("".join(multi_container)) == target_len:
                    multi_list.append(self.__calc_prob(copy.deepcopy(multi_container)))
                multi_container.pop()
                # return multi_container

                # Need to recursivly look for a multiword in the remainder

                self._augmented_identify_multi(right, multi_list, multi_container, target_len, threshold)

                if len("".join(multi_container)) == target_len:
                    multi_list.append(self.__calc_prob(copy.deepcopy(multi_container)))
                multi_container.pop()

                # If results indicate a parsing for the end of the alpha_string
                # It was a successful multi_word so return it as a list
                # if results:
                #     results.insert(0, alpha_string[0:index])
                #     return results

        # Could not parse out multi-words
        return
        pass

    # Detects if the input is a multi-word and if so, returns the base words
    #
    # alpha_string: Note making this explicit that only alpha strings should
    #               be passed in. The goal of this function is *not* to parse
    #               out digits, special characters, etc
    #
    #               Note: This can be a string OR a list of one character
    #                     items.
    #
    # I'm overloading the multiword detector usage to also be able to detect
    # base words as well. This can be useful for things like l33t manling.
    #
    # Because of that it returns two variables. The first one is a True/False
    # of it the multiword detector could parse the word, the second is the
    # parsing of the multiword itself.
    #
    # Returns 2 variables:
    #     If_Parsed [Parsing of word]
    #
    #     If_Parsed = True if the parsing found a multi-word or a base word
    #
    #     If_Parsed = False if no parsing or base word was found
    #
    #     [alpha_string]: if the alpha_string was not a multi-word
    #     [base_word,base_word,...]: List of base words making up the multi-word
    #
    def parse(self, alpha_string, threshold=0):

        # Quick bail out if the input password is too short or too long

        # Checking the base len so that we can still check if the string
        # is a base word.
        if len(alpha_string) < self.min_len:
            return False, [alpha_string]

        if len(alpha_string) >= self.max_len:
            return False, [alpha_string]

        # If the alpha_string has been seen enough to not be categorized as
        # a multi-word
        if self._get_count(alpha_string) >= self.threshold:
            return True, [alpha_string]

        # Bail out if the input password is too short to be a multi-word
        # if len(alpha_string) < self.min_check_len:
        #     return False, [alpha_string]

        # May be a multi-word. Need to parse it for possible base strings
        result = []
        self._augmented_identify_multi(alpha_string, result, [], len(alpha_string), threshold=threshold)
        result = sorted(result, key=lambda x: x[1], reverse=True)
        # No multiword parsing found
        if not result:
            return False, [alpha_string]

        # A multi-word parsing was found
        else:
            return True, result[0][0]

    def parse_sections(self, sections):
        parsed = []
        extracted_digits = []
        extracted_specials = []
        extracted_letters = []
        extracted_mask = []
        for sec, tag in sections:
            if tag is not None:
                parsed.append((sec, tag))
                continue
            parts = split_ado(sec)
            for part in parts:
                is_multi, multi_words = self.parse(part)
                for t in multi_words:
                    if t.isalpha():
                        lower_t = t.lower()
                        parsed.append((lower_t, f"A{len(lower_t)}"))
                        extracted_letters.append(lower_t)
                        mask = ""
                        for c in t:
                            if c.isupper():
                                mask += "U"
                            else:
                                mask += "L"
                        extracted_mask.append(mask)
                    elif t.isdigit():
                        parsed.append((t, f"D{len(t)}"))
                        extracted_digits.append(t)
                    else:
                        parsed.append((t, f"O{len(t)}"))
                        extracted_specials.append(t)
        return parsed, extracted_letters, extracted_mask, extracted_digits, extracted_specials
        pass

    def new_lendict(self):
        lendict = {}
        for dic in [self.dtree, self.__min_len_dtree]:
            for k, v in dic.items():
                lk = len(k)
                if lk not in lendict:
                    lendict[lk] = {}
                lendict[lk][k] = dic[k]
            for lk, ks in lendict.items():
                total = sum(ks.values())
                for k, v in ks.items():
                    lendict[lk][k] = v / total
            pass

        self.lendict = lendict
        pass


path_found_l33t = os.path.join(os.path.dirname(__file__), "l33t.found")
path_ignore_l33t = os.path.join(os.path.dirname(__file__), "l33t.ignore")
print(path_ignore_l33t)


def load_l33t_found() -> Set[str]:
    """
    words in this set will be treated as l33t and will not be parsed again
    :return: set of l33ts
    """
    if not os.path.exists(path_found_l33t):
        return set()
    fd = open(path_found_l33t, "r")
    l33ts = set()
    for line in fd:
        l33ts.add(line.strip("\r\n"))
    fd.close()
    return l33ts


def load_l33t_ign() -> Set[str]:
    """
    l33t.ignore, one instance per line
    :return: set of ignored l33ts
    """
    if not os.path.exists(path_ignore_l33t):
        return set()
    fd = open(path_ignore_l33t, "r")
    ign = set()
    for line in fd:
        ign.add(line.strip("\r\n"))
    return ign


def save_l33t_found(l33ts: Dict[str, int]) -> None:
    """
    give me a dict of l33ts, save it
    :param l33ts: l33ts got
    :return:
    """
    fd = open(path_found_l33t, "wb")
    l33ts = set(l33ts.keys())
    pickle.dump(l33ts, fd)


# this is a hack
re_invalid = re.compile(
    r"^("
    r".{1,3}"
    r"|[\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e0-9]+[a-z]+"  # except (S or D) + L
    r"|[a-z]+[\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e0-9]+"  # except L + (S or D)
    r"|.*[i1l|]{3,}.*"  # except il|a, il|b
    r"|[a-z0-9]{1,2}4(ever|life)"  # except a4ever, b4ever
    r")$")
# ignore words in this set
ignore_set = load_l33t_ign()
# words in this set will be treated as l33t and will not detect again.
# to speedup
valid_set = load_l33t_found()


def limit_alpha(word: str):
    """
    word is not composed of pure alphas
    word should have at last one alpha
    word.isdigit() is a speedup for pure digits
    :param word:
    :return:
    """
    return word.isalpha() or word.isdigit() or all([not c.isalpha() for c in word])


def invalid(word: str):
    """
    whether this word can be treated as l33t
    There are many trade-offs, to reject false positives
    :param word:
    :return:
    """
    lower = word.lower()
    if lower in ignore_set:
        return True
    # length ~ [4, 20]
    if len(word) < 4 or len(word) > 20:
        return True
    # pure alphas, pure digits, or pure others
    if limit_alpha(word):
        return True
    if word.startswith("#1") or word.endswith("#1"):
        return True
    counter = collections.Counter(lower)
    # 5i5i5i5i, o00oo0o
    if 2 == len(counter) or 2 <= len(word) // len(counter) <= min(counter.values()):
        return True
    return re_invalid.search(lower)


class AsciiL33tDetector:

    def __init__(self, multi_word_detector):
        """
        multi_word detector should be instance of my_multiword_detector.py
        :param multi_word_detector: instance of my_multiword_detector.py
        """
        self.multi_word_detector = multi_word_detector

        self.replacements = {
            '/-\\': ['a'],
            "/\\": ['a'],
            "|3": ['b'],
            "|o": ['b'],
            "(": ['c', 'g'],
            "<": ['c'],
            "k": ['c', 'k'],
            "s": ['c', 's'],
            "|)": ['d'],
            "o|": ["d"],
            "|>": ['d'],
            "<|": ["d"],
            "|=": ['f'],
            "ph": ['f', 'ph'],
            "9": ['g'],
            "|-|": ['h'],
            "]-[": ['h'],
            '}-{': ['h'],
            "(-)": ['h'],
            ")-(": ['h'],
            "#": ['h'],
            "l": ['i', 'l'],
            "|": ['i', 'l'],
            "!": ['i'],
            "][": ['i'],
            "i": ['l'],
            "_|": ['j'],
            "|<": ['k'],
            "/<": ['k'],
            "\\<": ['k'],
            "|{": ['k'],
            "|_": ['l'],
            "|v|": ['m'],
            "/\\/\\": ['m'],
            "|'|'|": ['m'],
            "(v)": ['m'],
            "/\\\\": ['m'],
            "/|\\": ['m'],
            '/v\\': ['m'],
            '|\\|': ['n'],
            "/\\/": ['n'],
            "|\\\\|": ['n'],
            "/|/": ['n'],
            "()": ['o'],
            "[]": ['o'],
            "{}": ['o'],
            "|2": ['p', 'r'],
            "|D": ["p"],
            "(,)": ['q'],
            "kw": ['q', 'kw'],
            "|z": ['r'],
            "|?": ['r'],
            "+": ['t'],
            "']['": ['t'],
            "|_|": ['u'],
            "|/": ['v'],
            "\\|": ['v'],
            "\\/": ['v'],
            "/": ['v'],
            "\\/\\/": ['w'],
            "\\|\\|": ['w'],
            "|/|/": ['w'],
            "\\|/": ['w'],
            "\\^/": ['w'],
            "//": ['w'],
            "vv": ['w'],
            "><": ['x'],
            "}{": ['x'],
            "`/": ['y'],
            "'/": ['y'],
            "j": ['y', 'j'],
            "(\\)": ['z'],
            '@': ['a'],
            '8': ['b', 'ate'],
            '3': ['e'],
            '6': ['b', 'g'],
            '1': ['i', 'l'],
            '0': ['o'],
            # '9': ['q'],
            '5': ['s'],
            '7': ['t'],
            '2': ['z', 'too', 'to'],
            '4': ['a', 'for', 'fore'],
            '$': ['s']
        }
        # to speedup match, not necessary
        repl_dict_tree = {}
        for repl, convs in self.replacements.items():
            tmp_d = repl_dict_tree
            for c in repl:
                if c not in tmp_d:
                    tmp_d[c] = {}
                tmp_d = tmp_d[c]
            tmp_d["\x02"] = convs
        self.repl_dict_tree = repl_dict_tree
        self.max_len_repl = len(max(self.replacements, key=lambda x: len(x)))
        # to speedup query
        self.l33t_map = {}
        # dict tree, to speedup detection
        self.dict_l33ts = {}
        # max len of l33t
        self.__min_l33ts = 4
        # min len of l33t
        self.__max_l33ts = 8
        # lower string

    def unleet(self, word: str) -> itertools.product:
        """
        1 may be converted to l and i, therefore at least one unleet word will be found
        this func will find all possible transformations.
        However, here is a hack to reject word with 256+ transformations
        :param word: l33t word
        :return: unleeted list
        """
        unleeted = []
        repl_dtree = self.repl_dict_tree
        i = 0
        while i < len(word):
            max_m = word[i]
            if max_m not in repl_dtree:
                unleeted.append([max_m])
                i += 1
                continue
            add_on = 1
            for t in range(2, self.max_len_repl + 1):

                n_key = word[i:i + t]
                if n_key not in self.replacements:
                    continue
                max_m = n_key
                add_on = t
            if max_m not in self.replacements:
                repl_list = [max_m]
            else:
                repl_list = self.replacements.get(max_m)
            i += add_on
            unleeted.append(repl_list)
        all_num = functools.reduce(lambda x, y: x * y, [len(p) for p in unleeted])
        # a hack, to early reject
        if all_num >= 256:
            return []
        all_possibles = itertools.product(*unleeted)
        return all_possibles

    def find_l33t(self, word: str) -> (bool, str):
        """
        whether a word is l33t or not
        return true if found.
        if you want, you can find all possible unleeted words
        :param word:
        :return: is l33t or not, unleeted word
        """

        unleeted_list = self.unleet(word)
        raw_leets = []
        for unleeted in unleeted_list:
            # unleeted = "".join(unleeted)
            if not "".join(unleeted).isalpha():
                continue
            next_i = 0
            for i in range(0, len(unleeted)):
                if i < next_i:
                    continue
                for j in range(len(unleeted), i + self.__min_l33ts - 1, -1):
                    substr = "".join(unleeted[i:j])
                    raw_word = word[i:j]
                    if len(substr) < self.__min_l33ts or invalid(raw_word):
                        break
                    count = self.multi_word_detector.get_count(substr)
                    if count >= self.multi_word_detector.threshold:
                        raw_leets.append(raw_word)
                        next_i = j
                        break
                    else:
                        next_i = i + 1
                        # return True, unleeted
                # valid.append((unleeted, count))
        return len(raw_leets) > 0, raw_leets

    def detect_l33t(self, pwd: str):
        """
        whether a given password is l33t.
        this is a hack, because I detect whether whole password is a l33t.
        Best way is to detect whether a password contains l33t part.
        this may be optimized later.
        :param pwd:
        :return:
        """
        lower_pwd = pwd.lower()
        if lower_pwd in valid_set and lower_pwd not in ignore_set:
            if lower_pwd not in self.l33t_map:
                self.l33t_map[lower_pwd] = 0
            # self.l33t_map[lower_pwd] += 1
            return
        if invalid(pwd):
            return
        # print("invalid cache failed")
        
        is_l33t, leets = self.find_l33t(lower_pwd)
        # print("leets", leets)
        if is_l33t:
            for leet in leets:
                if leet not in self.l33t_map:
                    self.l33t_map[leet] = 0
            # self.l33t_map[lower_pwd] += 1
            pass
        pass

    def init_l33t(self, training_set, encoding):
        """
        find l33ts from a training set
        :param training_set:
        :param encoding:
        :return:
        """
        if encoding.lower() != 'ascii':
            raise Exception("l33t detector can be used in ASCII-encoded passwords")
        file_input = open(training_set, encoding=encoding)
        num_parsed_so_far = 0
        try:
            password = file_input.readline()
            password = password.strip("\r\n")
            while password:
                # Print status indicator if needed
                num_parsed_so_far += 1
                if num_parsed_so_far % 1000000 == 0:
                    print(str(num_parsed_so_far // 1000000) + ' Million')
                # pcfg_parser.parse(password)
                self.detect_l33t(password)
                # Get the next password
                password = file_input.readline()
                password = password.strip("\r\n")

        except Exception as msg:
            traceback.print_exc(file=sys.stdout)
            print("Exception: " + str(msg))
            print("Exiting...")
            return
        print(f"init l33t done", file=sys.stderr)
        self.gen_l33t_dtree()
        pass

    def gen_l33t_dtree(self):
        """
        generate a dict tree, to speedup detection of part of l33t in a password
        :return:
        """
        l33ts = sorted(self.l33t_map.keys(), key=lambda x: len(x), reverse=True)
        if len(l33ts) == 0:
            return
        self.__min_l33ts = len(l33ts[-1])
        self.__max_l33ts = len(l33ts[0])
        for l33t in l33ts:
            # early return, a hack
            if len(l33t) < 2 * self.__min_l33ts:
                break
            for i in range(self.__min_l33ts, len(l33t) - self.__min_l33ts + 1):
                left = l33t[:i]
                right = l33t[i:]
                """
                some l33t may be composed of several short l33ts, remove them
                """
                if left in self.l33t_map and self.multi_word_detector.get_count(right) >= 5:
                    del self.l33t_map[l33t]
                    print(f"we delete {l33t} ")
                    break
                if right in self.l33t_map and self.multi_word_detector.get_count(left) >= 5:
                    del self.l33t_map[l33t]
                    print(f"we delete {l33t} ")
                    break
        for l33t in self.l33t_map:
            dict_l33t = self.dict_l33ts
            for c in l33t:
                if c not in dict_l33t:
                    dict_l33t[c] = {}
                dict_l33t = dict_l33t[c]
            dict_l33t["\x03"] = True
        pass

    def extract_l33t(self, pwd) -> List[Tuple[int, int, bool]]:
        """
        find the longest match of l33t, using DFS
        :param pwd:  password to be identified
        :return: list of [start_idx, len_of_seg, is_l33t]
        """
        l33t_list = []
        # candidate for a l33t
        a_l33t = ""
        # dict tree for l33ts, to speedup
        dict_l33ts = self.dict_l33ts
        lower_pwd = pwd.lower()
        len_pwd = len(pwd)
        i = 0
        cur_i = i
        len_l33ted = 0
        while i < len_pwd and cur_i < len_pwd:
            c = lower_pwd[cur_i]
            if c in dict_l33ts:
                a_l33t += c
                dict_l33ts = dict_l33ts[c]
                if "\x03" in dict_l33ts:
                    add_a_l33t = ""
                    bak_add_a_l33t = ""
                    for addi in range(cur_i + 1, min(cur_i + self.__max_l33ts - len(a_l33t) + 1, len_pwd)):
                        addc = lower_pwd[addi]
                        if addc not in dict_l33ts:
                            break
                        dict_l33ts = dict_l33ts[addc]
                        add_a_l33t += addc
                        if "\x03" in dict_l33ts:
                            bak_add_a_l33t = add_a_l33t
                        pass
                    if bak_add_a_l33t != "":
                        a_l33t += bak_add_a_l33t
                        cur_i += len(bak_add_a_l33t)
                    # find a l33t
                    len_a_l33t = len(a_l33t)
                    l33t_list.append((cur_i - len_a_l33t + 1, len_a_l33t, True))
                    # if len_l33ted == pwd_len, return, else, add not_l33t parts
                    len_l33ted += len_a_l33t
                    # successfully find a l33t, move forward i
                    i += len_a_l33t
                    cur_i = i
                    # used to find not_l33t
                    a_l33t = ""
                    dict_l33ts = self.dict_l33ts
                cur_i += 1
            else:
                i += 1
                cur_i = i
                a_l33t = ""
                dict_l33ts = self.dict_l33ts
        if len_l33ted == len_pwd:
            return l33t_list
        elif len(l33t_list) == 0:
            return [(0, len_pwd, False)]
        else:
            n_list = set()
            is_l33t_set = set()
            n_list.add(0)
            for i, sl, is_l33t in l33t_list:
                n_list.add(i)
                n_list.add(i + sl)
                is_l33t_set.add(i)
            n_list.add(len_pwd)
            n_list = sorted(n_list)
            n_l33t_list = []
            for n_i, pwd_i in enumerate(n_list[:-1]):
                n_l33t_list.append((pwd_i, n_list[n_i + 1] - pwd_i, pwd_i in is_l33t_set))
            return n_l33t_list
        pass

    def parse(self, password):
        """
        parsing a password, may be a section of password
        :param password:
        :return: section tag, l33ts, masks
        """
        if password in self.l33t_map:
            return [(password, f"A{len(password)}")], [password], [get_mask(password)]

        l33t_list = self.extract_l33t(password)
        if len(l33t_list) == 0:
            return [(password, None)], [], []
        l33t_list = sorted(l33t_list, key=lambda x: x[0])
        section_list = []
        leet_list = []
        mask_list = []
        for idx, len_l33t, is_l33t in l33t_list:
            leet = password[idx:idx + len_l33t]
            if is_l33t:
                lower_leet = leet.lower()
                section_list.append((lower_leet, f"A{len(lower_leet)}"))
                leet_list.append(lower_leet)
                mask = get_mask(leet)
                mask_list.append(mask)
            else:
                section_list.append((leet, None))
        return section_list, leet_list, mask_list

    def parse_sections(self, sections):
        """
        given a sections list, find and tag possible l33ts, and return a new sections list
        :param sections:
        :return:
        """
        parsed_sections = []
        parsed_l33t = []
        parsed_mask = []
        for section, tag in sections:
            if tag is not None:
                parsed_sections.append((section, tag))
                continue
            if len(section) < self.__min_l33ts or limit_alpha(section):
                parsed_sections.append((section, None))
                continue
            section_list, leet_list, mask_list = self.parse(section)
            parsed_sections.extend(section_list)
            parsed_l33t.extend(leet_list)
            parsed_mask.extend(mask_list)
        return parsed_sections, parsed_l33t, parsed_mask


def obtain_leet_detector(corpus: str) -> AsciiL33tDetector:
    multiword_detector = MyMultiWordDetector()
    with open(corpus) as fd:
        for line in fd:
            line = line.strip("\r\n")
            multiword_detector.train(line)
    leet_detector = AsciiL33tDetector(multi_word_detector=multiword_detector)
    leet_detector.init_l33t(training_set=corpus, encoding='ascii')
    return leet_detector
    pass


def wrapper():
    cli = argparse.ArgumentParser("Leet Identification")
    cli.add_argument("-c", "--corpus", dest="corpus", type=str, required=True,
                     help="Training dataset for leet identification. "
                          "We first collect leet patterns from training sets, "
                          "then identify these leet patterns from given passwords.")
    cli.add_argument("-p", "--pwd-set", dest="pwd_set", type=argparse.FileType('r'), required=True,
                     help="Given passwords. We will identify leet patterns from these passwords.")
    cli.add_argument("-o", "--output", dest="output", type=argparse.FileType('w'), required=True,
                     help="Leet patterns identified from given passwords will appear in this file. "
                          "Note that the 4th line is the start of the identified leet patterns.")
    args = cli.parse_args()
    f_out = args.output  # type: TextIO
    if not f_out.writable():
        print(f"{f_out.name} is not writable", file=sys.stderr)
        sys.exit(-1)
    leet_detector = obtain_leet_detector(corpus=args.corpus)
    pwd_set = args.pwd_set  # type: TextIO
    pwd_dict = collections.defaultdict(int)
    for pwd in pwd_set:
        pwd = pwd.strip("\r\n")
        pwd_dict[pwd] += 1
        # print(leet_patterns, mask_lists)
    containing_leet = 0
    total = sum(pwd_dict.values())
    leet_dict = {**leet_detector.l33t_map}
    for pwd, cnt in pwd_dict.items():
        _, leet_pattern_list, mask_list = leet_detector.parse(pwd)
        if len(leet_pattern_list) > 0:
            containing_leet += cnt
        for leet_pattern in leet_pattern_list:
            leet_dict[leet_pattern] += cnt
    info = f"Containing leet patterns: {containing_leet},\n" \
           f"Total passwords: {total},\n" \
           f"Proportion: {containing_leet / total * 100:7.4f}\\%"
    print(info)
    print(info, file=f_out)
    for leet_pattern, num in sorted(leet_dict.items(), key=lambda x: x[1], reverse=True):
        if num > 0:
            f_out.write(f"{leet_pattern}\t{num}\t{num / total * 100:7.4f}\n")
        else:
            break
    f_out.flush()
    f_out.close()

    pass


def wrapper4chunks():
    cli = argparse.ArgumentParser("Leet Identification")
    cli.add_argument("-c", "--corpus", dest="corpus", type=str, required=True,
                     help="Training dataset for leet identification. "
                          "We first collect leet patterns from training sets, "
                          "then identify these leet patterns from given passwords.")
    cli.add_argument("--chunks", dest="chunks", type=argparse.FileType('r'), required=True,
                     help="Given chunks. We will identify leet patterns from these chunks.")
    cli.add_argument("-o", "--output", dest="output", type=argparse.FileType('w'), required=True,
                     help="Chunks which follow the leet patterns will appear in this file. "
                          "Note that the 4th line is the start of the identified leet patterns.")
    cli.add_argument('-p','--pickle', dest='pickle', type=str, required=False, default=None,
                     help="read the model from dumped pickle file")
    args = cli.parse_args()
    f_out = args.output  # type: TextIO
    if not f_out.writable():
        print(f"{f_out.name} is not writable", file=sys.stderr)
        sys.exit(-1)
    dumped = args.pickle
    if dumped is None:
        leet_detector = obtain_leet_detector(corpus=args.corpus)
    else:
        if not os.path.exists(dumped):
            leet_detector = obtain_leet_detector(corpus=args.corpus)
            fd = open(dumped, 'wb')
            pickle.dump(leet_detector, fd)
            fd.close()
        leet_detector = pickle.load(open(dumped, 'rb'))

    pwd_set = args.chunks  # type: TextIO
    chunk_dict = collections.defaultdict(int)
    for line in pwd_set:
        line = line.strip("\r\n")
        chunk, cnt = line.split(' ')
        chunk = chunk.strip('\x01')
        chunk_dict[chunk] += int(cnt)
        # print(leet_patterns, mask_lists)
    containing_leet = 0
    total = sum(chunk_dict.values())
    leet_dict = {**leet_detector.l33t_map}
    for valid_leet in valid_set:
        leet_dict[valid_leet] = 0
    # if True:
    #     return
    # print(leet_dict)
    res = collections.defaultdict(int)
    for chunk, cnt in chunk_dict.items():
        lchunk = chunk.lower()
        if lchunk in leet_dict and lchunk not in ignore_set:
            res[chunk] += cnt
            containing_leet += cnt
            # print(chunk, cnt, leet_dict[chunk])
    info = f"Containing leet patterns: {containing_leet},\n" \
           f"Total passwords: {total},\n" \
           f"Proportion: {containing_leet / total * 100:7.4f}\\%"
    print(info)
    print(info, file=f_out)
    for leet_pattern, num in sorted(res.items(), key=lambda x: x[1], reverse=True):
        if num > 0:
            f_out.write(f"{leet_pattern}\t{num}\t{num / total * 100:7.4f}\n")
        else:
            break
    f_out.flush()
    f_out.close()

    pass


def test_unleet():
    ttt = AsciiL33tDetector(None)
    t111 = ttt.unleet("_love")
    for iii in t111:
        if not "".join(iii).isalpha():
            continue
        print(iii)
    pass


if __name__ == '__main__':
    wrapper4chunks()
    pass
