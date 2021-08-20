import sys
from math import log2
from typing import Any, Tuple


def luds(pwd: str):
    """
    Get LUDS representation of a password.
    pwd: Password we need to handle.

    return: A tuple of segment list, which contains a pair of PCFG tag and length of the tag.
    """
    struct = []
    prev_tag = ""
    t_len = 0
    cur_tag = " "
    for c in pwd:
        if c.isalpha():
            if c.isupper():
                cur_tag = "U"
            else:
                cur_tag = "L"
        elif c.isdigit():
            cur_tag = "D"
        else:
            cur_tag = "S"
        if cur_tag == prev_tag:
            t_len += 1
        else:
            if len(prev_tag) > 0:
                struct.append((prev_tag, t_len))
            prev_tag = cur_tag
            t_len = 1
    struct.append((cur_tag, t_len))
    return tuple(struct)


def calc_ml2p(__converted, __not_parsed, grammars, terminals, pwd: str) -> Tuple[Any, float]:
    """
    Calculate probability of given password. 
    converted: The template has already converted.
    __not_parsed: The templates which are not converted.
    grammars: The structures of PCFG model.
    terminals: The segments information of PCFG model.
    pwd: Input password which is a simple string

    return: The final template of the password and its maximal probability.
    """
    get_luds = luds(pwd)
    # get luds structures
    label = get_luds
    candidate_structures = __converted.get(label, set())
    log_max = -log2(sys.float_info.min)
    if len(candidate_structures) == 0:
        length = sum([_len for _, _len in label])
        addon_candidate_structures = __not_parsed.get(length, set())
        candidate_structures.update(addon_candidate_structures)
        if len(candidate_structures) == 0:
            return get_luds, log_max
    results = []
    for candidate in candidate_structures:
        p = grammars.get(candidate, log_max)
        if p == log_max:
            break
        start = 0
        for tag, t_len in candidate:
            terminal = terminals.get((tag, t_len))
            replacement = pwd[start:start + t_len]
            start += t_len
            if replacement not in terminal:
                p = log_max
                break
            else:
                p += terminal[replacement]
        if p < log_max:
            results.append((candidate, p))
    if len(results) == 0:
        min_minus_log_prob = log_max
        candidate = get_luds
    else:
        candidate, min_minus_log_prob = min(results, key=lambda x: x[1])
        # candidate = [f"{tag}{t_len}" for tag, t_len in candidate]
    return candidate, min_minus_log_prob
