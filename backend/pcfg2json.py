import os
import pickle
import re
import sys
import json
import math
import hashlib

from collections import defaultdict
from typing import Dict, Tuple, Any

def md5_hash_function(segment:str):
    return hashlib.md5(segment.encode("utf8")).hexdigest()[12:-12]

def default_hash_function(segment:str):
    return segment

def hash_function(segment:str):
    return md5_hash_function(segment)

def tuple_to_string(data:Tuple):
    if len(data) == 0:
        return ""
    if type(data[0]) == tuple:
        return "".join([tuple_to_string(x) for x in data])
    return "".join([str(x) for x in data])

def check_path_exists(_path: str):
    if not os.path.exists(_path):
        print(f"{_path} not exists, exit.", file=sys.stderr)
        sys.exit(-1)
    pass


def read_tag(tag_path: str, tag: str) -> Dict[Tuple[str, int], Dict[str, float]]:
    check_path_exists(tag_path)
    tag_dict = defaultdict(lambda: defaultdict(float))
    hash_dict = defaultdict(lambda: set())
    conflict = 0
    for root, dirs, files in os.walk(tag_path):
        for file in files:
            dot_idx = file.find(".")
            tag_len = (tag, int(file[:dot_idx]))
            tag_len = tuple_to_string(tag_len)
            fd = open(os.path.join(root, file))
            for _line in fd:
                _tag, prob = _line.strip("\r\n").split("\t")
                segment = hash_function(_tag)
                if segment in hash_dict[tag_len]:
                    conflict += 1
                hash_dict[tag_len].add(segment)
                tag_dict[tag_len][segment] = -math.log2(float(prob))
                # tag_dict[tuple_to_string(tag_len)][_tag] = 0
            fd.close()
    print("Conflict checking: ",tag, conflict)
    return tag_dict


def read_grammars(gram_path: str):
    fd = open(gram_path)
    structure_prob_dict = {}
    re_tag_len = re.compile(r"([A-Z]+[0-9]+)")
    re_tag = re.compile(r"[A-Z]+")
    re_len = re.compile(r"[0-9]+")
    for _line in fd:
        raw_structure, prob = _line.strip("\r\n").split("\t")
        structure = tuple_to_string(tuple(
            [(re_tag.search(t).group(), int(re_len.search(t).group())) for t in re_tag_len.split(raw_structure) if
             len(t) > 0]))
        structure_prob_dict[structure] = -math.log2(float(prob))
        # structure_prob_dict[structure] = 0

    fd.close()
    return structure_prob_dict


def read_bpe(model_path: str) -> Tuple[Dict[Any, float], Dict[Tuple[str, int], Dict[Any, float]]]:
    """
    :param model_path:
    :return: (grammars, terminals)
        the grammars is a dict of structures and corresponding probabilities, such as
        ((D, 10), (D, 1), (L, 3)): 1.556e-7
        the terminals is a dict of tag (such as (D, 10)) and corresponding replacements
        and probabilities, such as (D, 10): {1234567890, 1.556e-7}
    """
    check_path_exists(model_path)
    _grammars = read_grammars(os.path.join(model_path, "grammar", "structures.txt"))
    _dicts = []
    lower = read_tag(os.path.join(model_path, "lower"), "L")
    upper = read_tag(os.path.join(model_path, "upper"), "U")
    double_m = read_tag(os.path.join(model_path, "mixed_2"), "DM")
    triple_m = read_tag(os.path.join(model_path, "mixed_3"), "TM")
    four_m = read_tag(os.path.join(model_path, "mixed_4"), "FM")
    digits = read_tag(os.path.join(model_path, "digits"), "D")
    special = read_tag(os.path.join(model_path, "special"), "S")
    # _terminals = {**lower, **upper, **double_m, **triple_m, **four_m, **digits, **special}
    _models = {
        "grammar":_grammars, 
        "lower": lower, 
        "upper": upper, 
        "double_m": double_m, 
        "triple_m": triple_m, 
        "four_m": four_m, 
        "digits": digits, 
        "special": special
    }
    return _models

def wrapper():
    models = read_bpe("/home/yujitao/OpenPSM/XmPSM/tmpmodel/model_E4.5")
    target_file = "./resources/pcfg_model.json"
    pickle_file = "./resources/ckl_pcfg_model.pickle"

    res = []
    # check pcfg model
    for k,v in models["grammar"].items():
        values = []
        for ch in k:
            if(not ch.isdigit() and (len(values) == 0 or len(values[-1]) > 0)):
                values.append("")
            if(ch.isdigit()):
                values[-1] += ch
        value = sum([int(x) for x in values])
        if(value == 6):
            res.append(k)
            # print(k)/=
    res.sort()
    # for item in res:
    #     print(item)
    print(len(res))

    with open(target_file, "w") as fd:
        json.dump(models, fd)

    pickle.dump(json.dumps(models), open(pickle_file, "wb"))

if __name__ == '__main__':
    wrapper()
