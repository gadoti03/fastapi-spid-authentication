from math import gcd


def count_freq(s):
    """Return frequency dictionary of characters in string"""
    freq = {}

    for c in s:
        if c not in freq:
            freq[c] = 0
        freq[c] += 1

    return freq


def gcd_list(values):
    """Compute gcd of a list of integers"""
    g = values[0]

    for v in values[1:]:
        g = gcd(g, v)

    return g


def max_equal_parts_for_prefixes(packages: str):

    n = len(packages)
    results = []

    for k in range(1, n + 1):

        prefix = packages[:k]
        freq = count_freq(prefix)

        g = gcd_list(list(freq.values()))

        best = 1

        for m in range(g, 0, -1):

            if k % m != 0:
                continue

            segment_len = k // m
            target = count_freq(prefix[:segment_len])

            valid = True

            for i in range(1, m):

                segment = prefix[i * segment_len:(i + 1) * segment_len]

                if count_freq(segment) != target:
                    valid = False
                    break

            if valid:
                best = m
                break

        results.append(best)

    return results


packages = "AAABBB"
print(max_equal_parts_for_prefixes(packages))