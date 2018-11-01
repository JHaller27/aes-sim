# Author: James Haller
from typing import Union

from utils import *

S_BOX = [
    ['63', '7C', '77', '7B', 'F2', '6B', '6F', 'C5', '30', '01', '67', '2B', 'FE', 'D7', 'AB', '76'],
    ['CA', '82', 'C9', '7D', 'FA', '59', '47', 'F0', 'AD', 'D4', 'A2', 'AF', '9C', 'A4', '72', 'C0'],
    ['B7', 'FD', '93', '26', '36', '3F', 'F7', 'CC', '34', 'A5', 'E5', 'F1', '71', 'D8', '31', '15'],
    ['04', 'C7', '23', 'C3', '18', '96', '05', '9A', '07', '12', '80', 'E2', 'EB', '27', 'B2', '75'],
    ['09', '83', '2C', '1A', '1B', '6E', '5A', 'A0', '52', '3B', 'D6', 'B3', '29', 'E3', '2F', '84'],
    ['53', 'D1', '00', 'ED', '20', 'FC', 'B1', '5B', '6A', 'CB', 'BE', '39', '4A', '4C', '58', 'CF'],
    ['D0', 'EF', 'AA', 'FB', '43', '4D', '33', '85', '45', 'F9', '02', '7F', '50', '3C', '9F', 'A8'],
    ['51', 'A3', '40', '8F', '92', '9D', '38', 'F5', 'BC', 'B6', 'DA', '21', '10', 'FF', 'F3', 'D2'],
    ['CD', '0C', '13', 'EC', '5F', '97', '44', '17', 'C4', 'A7', '7E', '3D', '64', '5D', '19', '73'],
    ['60', '81', '4F', 'DC', '22', '2A', '90', '88', '46', 'EE', 'B8', '14', 'DE', '5E', '0B', 'DB'],
    ['E0', '32', '3A', '0A', '49', '06', '24', '5C', 'C2', 'D3', 'AC', '62', '91', '95', 'E4', '79'],
    ['E7', 'C8', '37', '6D', '8D', 'D5', '4E', 'A9', '6C', '56', 'F4', 'EA', '65', '7A', 'AE', '08'],
    ['BA', '78', '25', '2E', '1C', 'A6', 'B4', 'C6', 'E8', 'DD', '74', '1F', '4B', 'BD', '8B', '8A'],
    ['70', '3E', 'B5', '66', '48', '03', 'F6', '0E', '61', '35', '57', 'B9', '86', 'C1', '1D', '9E'],
    ['E1', 'F8', '98', '11', '69', 'D9', '8E', '94', '9B', '1E', '87', 'E9', 'CE', '55', '28', 'DF'],
    ['8C', 'A1', '89', '0D', 'BF', 'E6', '42', '68', '41', '99', '2D', '0F', 'B0', '54', 'BB', '16']
]


def s_get(byte: int) -> int:
    byte = i2h(byte, 2)
    row, col = h2i(byte[0]), h2i(byte[1])
    return h2i(S_BOX[row][col])


class RoundCoefficient:
    __slots__ = ['_val']

    def __init__(self):
        self._val = 1
        
    def _inc_val(self) -> None:
        # Left bit-shift
        bits = self._val * 2
        
        # Mod div by AES coefficient
        _, bits = polynomial_div(bits, AES_POLYNOMIAL)

        self._val = bits

    def get_val(self) -> int:
        x = self._val
        self._inc_val()
        return x


"""=============================================================================="""


class GFunction:
    """
    GoF Context class
    """
    data: Union[int, list]

    __slots__ = ['_step', '_rc', 'data']

    def __init__(self):
        self._step = None
        self._rc = RoundCoefficient()
        self.data = None

    def get_result(self, key: int) -> int:
        self.data = key
        self._step = StartGFunction(self)
        while self._step is not None:
            self._step = self._step.run()

        return self.data

    def get_round_coefficient(self) -> int:
        return self._rc.get_val()


"""=============================================================================="""


class FunctionStep:
    """
    GoF State super-class.
    """
    _context: GFunction
    __slots__ = ['_context']

    def __init__(self, context: GFunction):
        self._context = context

    def run(self):
        raise NotImplementedError


class StartGFunction(FunctionStep):
    def run(self):
        return Split(self._context)


class Split(FunctionStep):
    NUM_CHUNKS = 4

    def run(self):
        self._context.data = i2b(self._context.data, WORD_SIZE * self.NUM_CHUNKS)

        data = self._context.data
        self._context.data = [data[j:j + WORD_SIZE] for j in range(0, len(data), WORD_SIZE)]
        self._context.data = [x for x in map(b2i, self._context.data)]
        
        return Shift(self._context)


class Shift(FunctionStep):
    def run(self):
        data = self._context.data
        size = len(data)
        self._context.data = [data[(idx + 1) % size] for idx in range(size)]
        
        return Substitution(self._context)


class Substitution(FunctionStep):
    def run(self):
        data = []
        for byte_datum in self._context.data:
            data.append(s_get(byte_datum))
        self._context.data = data

        return Xor(self._context)


class Xor(FunctionStep):
    def run(self):
        self._context.data[0] = self._context.data[0] ^ self._context.get_round_coefficient()

        return Recombine(self._context)


class Recombine(FunctionStep):
    def run(self):
        data = ''
        for byte_datum in self._context.data:
            data += i2h(byte_datum)
        self._context.data = h2i(data)

        return None


if __name__ == '__main__':
    g = GFunction()
    for i in range(10 + 1):
        key = i2h(g.get_result(), WORD_SIZE * 4 // 4)  # 4 words, 4 bits/hex digit
        chunk_size = 2
        key_lst = [key[j:j + chunk_size] for j in range(0, len(key), chunk_size)]
        print('[{:02}] = {}'.format(i, ' '.join(key_lst)))
