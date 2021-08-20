import pickle
from hashlib import md5
import os

from monte_carlo_lib import MonteCarloLib
from fast_bpe_sim import calc_ml2p

current_dir = os.path.dirname(__file__)
grammars, terminals = pickle.load(open(os.path.join(current_dir, "resources/bpemodel.pickle"), 'rb'))
converted, not_parsed = pickle.load(open(os.path.join(current_dir, "resources/intermediate_results.pickle"), 'rb'))
dangerous_chunks = pickle.load(open(os.path.join(current_dir,"resources/dangerous_chunks.pickle"), 'rb'))
monte_carlo_sample = pickle.load(open(os.path.join(current_dir, "resources/monte_carlo_sample.pickle"), 'rb'))
monte_carlo = MonteCarloLib(monte_carlo_sample)

def check_pwd(pwd: str):
    """Check the strength of given password.
    Given a password which is encoded by ascii and return strength information of the password.

    Arguments:
        pwd: The input password we need to check.
    
    Returns:
        A tuple which is consist of guess_number, segments, chunks and prob. 
        The guess_number indicates the maximal guess number of given password.
        The segments indicates the all segments.
        The chunks indicates that all dangerous chunks in the password.
        The prob is the guess probability of the password which is calculated by monte carlo method.
    """
    struct, prob = calc_ml2p(converted, not_parsed, grammars, terminals, pwd)
    chunks = []
    prev = 0
    for _, l in struct:
        sc = pwd[prev:prev + l]
        prev += l
        if sc in dangerous_chunks:
            _a = (sc, True)
        else:
            _a = (sc, False)
        chunks.append(_a)
    rank = monte_carlo.ml2p2rank(prob)
    return {
        "guess_number": rank,
        "segments": struct,
        "chunks": chunks,
        "prob": 2 ** -prob,
    }

def is_dangerous_chunk(chunk:str):
    return chunk in dangerous_chunks
