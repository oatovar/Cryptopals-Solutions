#!/usr/bin/env python3

# Cryptopals Set 1 Challenge 4

if __name__ == '__main__':
    from c3 import singlebyte_xor_solve, beautify
    with open('c4_input.txt', 'r') as file:
        results = []
        for line in file:
            result = singlebyte_xor_solve(line)
            results.append(result)
        sorted_results = sorted(results, key=lambda r: r['score'], reverse=True)
        winner = sorted_results[0]
        print('Problem #4 =>', beautify(winner))

