# Author: James Haller


WORD_SIZE = 8

AES_POLYNOMIAL = 0b100011011


def polynomial_div(x: int, y: int) -> (int, int):
    """
    Finds the quotient of x/y using xor in place of subtraction in long-division
    :param x: Divisor
    :param y: Dividend
    :return: (quotient, remainder)
    """
    x, y = i2b(x), i2b(y)
    q = '0' * len(y)
    while len(x) >= len(y):
        # Pad y w/ trailing 0s (ie left shift)
        pad_dist = 1
        y_padded = y
        while len(y_padded) < len(x):
            y_padded = y_padded + '0'
            pad_dist += 1

        # Set quotient bit
        q_lst = [b for b in q]
        q_lst[-pad_dist] = '1'
        q = ''.join(q_lst)

        # Subtraction
        x = i2b(b2i(x) ^ b2i(y_padded))

        # Trim leading 0s from remainder
        trim_idx = 0
        while x[trim_idx] != '1':
            trim_idx += 1
        x = x[trim_idx:]

    return b2i(q), b2i(x)


def h2i(h: str) -> int:
    return int(h, 16)


def i2h(i: int, num_digits: int=0) -> str:
    return '{:0{}X}'.format(i, num_digits)


def b2i(b: str) -> int:
    return int(b, 2)


def i2b(i: int, num_digits: int =0) -> str:
    return '{:0{}b}'.format(i, num_digits)
