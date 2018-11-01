# Author: James Haller

"""
Uses Gang-of-Four State pattern to retrieve DES keys **in order**.
"""
from typing import Union

import gfunction
from utils import *

NUM_CHUNKS = 4


class KeyScheduler:
    """
    GoF Context class.
    """
    __slots__ = ['_step', '_g_function', 'round_num', 'data']

    def __init__(self, key: int):
        self._step = None
        self.round_num = 0
        self.data: Union[int, list] = key
        self._g_function = gfunction.GFunction()

    def _transform(self):
        self._step = StartKeyRound(self)
        while self._step is not None:
            self._step = self._step.run()

    def _get_merged_round_key(self):
        k = ''
        for i in range(NUM_CHUNKS):
            k += i2b(self.data[self.round_num * NUM_CHUNKS + i], WORD_SIZE * 4)
        return b2i(k)

    def get_round_key(self):
        self._transform()
        k = self._get_merged_round_key()
        self.round_num += 1
        return k

    def get_g_function_ref(self):
        return self._g_function.get_result


"""=============================================================================="""


class RoundStep:
    """
    GoF State super-class.
    """
    __slots__ = ['_context']

    def __init__(self, scheduler: KeyScheduler):
        self._context = scheduler

    def run(self):
        raise NotImplementedError


class StartKeyRound(RoundStep):
    def run(self):
        return Split(self._context) if self._context.round_num == 0 else Transform(self._context)


class Split(RoundStep):
    def run(self):
        self._context.data = i2b(self._context.data, KEY_SIZE)

        data = self._context.data
        self._context.data = [data[j:j + KEY_SIZE // 4] for j in range(0, len(data), KEY_SIZE // 4)]
        self._context.data = [x for x in map(b2i, self._context.data)]

        return None


class Transform(RoundStep):
    def run(self):
        # W[4i] = W[4(i−1)]+g(W[4i−1])
        W = self._context.data
        i = self._context.round_num
        g = self._context.get_g_function_ref()
        W.append(W[4*(i-1)] ^ g(W[4*i-1]))

        # W[4i + j] = W[4i+j−1]+W[4(i−1)+j]
        for j in range(1, 4):
            W.append(W[4*i+j-1] ^ W[4*(i-1)+j])

        # lists are pass-by-ref, so W.append() will also append to _context.data

        return None


if __name__ == '__main__':
    ks = KeyScheduler(0)
    for i in range(1 + 1):
        key = i2h(ks.get_round_key(), KEY_SIZE // 4)  # 4 bits/hex digit
        chunk_size = 2
        key_lst = [key[j:j + chunk_size] for j in range(0, len(key), chunk_size)]
        print('[{:02}] = {}'.format(i, ' '.join(key_lst)))
