import bisect
from math import log2, ceil
import pickle
from typing import List, Tuple, TextIO
import random

def my_cumsum(lst: List[float]):
    if len(lst) <= 0:
        return []
    acc = 0
    cumsum = []
    for v in lst:
        acc += v
        cumsum.append(acc)
    return cumsum

def equals(num1:float, num2:float,delta=0.00000001):
    return abs(num1-num2) < delta

class MonteCarloLib:
    def __init__(self, minus_log_prob_list: List[float]):
        minus_log_prob_list.sort()
        self.__minus_log_prob_list = minus_log_prob_list
        minus_log_probs, positions = self.__gen_rank_from_minus_log_prob()
        self.__minus_log_probs = minus_log_probs
        self.__positions = positions
        self.__gc = None
        pass

    def __gen_rank_from_minus_log_prob(self) -> Tuple[List[float], List[float]]:
        """
        calculate the ranks according to Monte Carlo method
        :return: minus_log_probs and corresponding ranks
        """
        minus_log_probs = [lp for lp in self.__minus_log_prob_list]
        minus_log_probs.sort()
        logn = log2(len(minus_log_probs))
        positions = my_cumsum([2 ** (mlp - logn) for mlp in minus_log_probs])
        # logn = log2(len(minus_log_probs))
        # positions = (2 ** (minus_log_probs - logn)).cumsum()
        return minus_log_probs, positions
        pass

    def ml2p2rank(self, minus_log_prob):
        idx = bisect.bisect_right(self.__minus_log_probs, minus_log_prob)
        return self.__positions[idx - 1] if idx > 0 else 1

    def ml2p_iter2gc(self, minus_log_prob_iter: List[Tuple[str, int, float]],
                     need_resort: bool = False, add1: bool = True) \
            -> List[Tuple[str, float, int, int, int, float]]:
        """

        :param add1: rank is larger than previous one
        :param need_resort:
        :param minus_log_prob_iter: sorted
        :return:
        """
        if need_resort:
            minus_log_prob_iter = sorted(minus_log_prob_iter, key=lambda x: x[2])
        gc = []
        prev_rank = 0
        cracked = 0
        total = sum([a for _, a, _ in minus_log_prob_iter])
        addon = 1 if add1 else 0
        for pwd, appearance, mlp in minus_log_prob_iter:
            idx = bisect.bisect_right(self.__minus_log_probs, mlp)
            rank = ceil(max(self.__positions[idx - 1] if idx > 0 else 1, prev_rank + addon))
            cracked += appearance
            prev_rank = rank
            gc.append((pwd, mlp, appearance, rank, cracked, cracked / total * 100))
        self.__gc = gc
        return gc

    def write2(self, fd: TextIO):
        if not fd.writable():
            raise Exception(f"{fd.name} is not writable")
        if self.__gc is None:
            raise Exception(f"run mlps2gc before invoke this method")
        for pwd, mlp, appearance, rank, cracked, cracked_ratio in self.__gc:
            fd.write(f"{pwd}\t{mlp:.8f}\t{appearance}\t{rank}\t{cracked}\t{cracked_ratio:5.2f}\n")
        self.__gc = None
        pass

    def to_dict(self):
        positions = []
        probs = []
        prev_position = 0
        prev_value = -1
        for i in range(len(self.__positions)):
            # for password with same probability we only count once.
            if equals(prev_value, self.__minus_log_probs[i]):
                continue
            # parse float position to integer type
            prev_position = max(int(self.__positions[i]), prev_position+1)
            # add position and probability to result list
            positions.append(prev_position)
            probs.append(self.__minus_log_probs[i])
            prev_value = self.__minus_log_probs[i]
        return {"positions":positions, "probs":probs}

def load_monte_carlo(path:str, dropout=0.75):
    samples = []
    with open(path, 'r') as fin:
        for line in fin:
            if random.random() >= dropout:
                samples.append(float(line.strip("\r\n")))
    monte_carlo = MonteCarloLib(minus_log_prob_list=samples)
    return monte_carlo

# if __name__ == '__main__':
#     model = load_monte_carlo("resources/tmpsamples.txt")
#     pickle.dump(model, open("resources/monte_carlo.pickle","wb"))
