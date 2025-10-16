#!/usr/bin/env python3
"""
EtTu.py — Caesar cipher brute-forcer (prints all shifts, recommends best).

Usage:
  python3 EtTu.py

Notes:
  Scores are relative heuristic values (0..1). They combine (a) fraction of common
  English words and (b) letter-frequency similarity. Higher ≈ more English-like.
  Short texts or proper nouns may yield lower absolute scores, but the correct
  decryption will typically appear among the highest-scoring results.
"""

import string
import textwrap
from collections import Counter
from typing import List, Tuple
import argparse

ENGLISH_FREQ = {
    'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23, 'G': 2.02,
    'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03, 'M': 2.41, 'N': 6.75,
    'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99, 'S': 6.33, 'T': 9.06, 'U': 2.76,
    'V': 0.98, 'W': 2.36, 'X': 0.15, 'Y': 1.97, 'Z': 0.07
}

COMMON_WORDS = {
    "the","and","that","have","for","not","with","you","this","but","his","from",
    "they","she","which","would","there","their","what","will","about","more","when",
    "make","can","like","time","just","know","take","people","into","year","your",
    "good","some","could","them","see","other","than","then","now","look","only",
    "come","its","over","think","also","back","after","use","two","how","our","work",
    "first","well","way","even","new","want","because","any","these","give","day",
    "most","us","is","in","on","it","a","an"
}

def caesar_shift(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            out.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
        else:
            out.append(ch)
    return ''.join(out)

def letter_frequency_score(text: str) -> float:
    letters = [c.upper() for c in text if c.isalpha()]
    N = len(letters)
    if N == 0:
        return 0.0
    counts = Counter(letters)
    chi_sq = 0.0
    for L, expected_pct in ENGLISH_FREQ.items():
        observed = counts.get(L, 0)
        expected = expected_pct / 100.0 * N
        chi_sq += ((observed - expected) ** 2) / (expected + 1e-9)
    return 1.0 / (1.0 + chi_sq)

def tokenize_words(text: str) -> List[str]:
    cur, words = [], []
    for ch in text.lower():
        if ch.isalpha() or ch == "'":
            cur.append(ch)
        else:
            if cur:
                words.append(''.join(cur))
                cur = []
    if cur:
        words.append(''.join(cur))
    return words

def common_word_score(text: str) -> float:
    words = tokenize_words(text)
    if not words:
        return 0.0
    matches = sum(1 for w in words if w in COMMON_WORDS)
    return matches / len(words)

def score_candidate(text: str, word_weight: float = 0.85) -> float:
    w = common_word_score(text)
    l = letter_frequency_score(text)
    return word_weight * w + (1.0 - word_weight) * l

def brute_force_all(ciphertext: str) -> List[Tuple[int, str, float]]:
    results = []
    for shift in range(26):
        plain = caesar_shift(ciphertext, shift)
        s = score_candidate(plain)
        results.append((shift, plain, s))
    return results

def main():
    parser = argparse.ArgumentParser(description="Caesar cipher brute-force decoder — shows all 26 shifts and recommends best match.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-s', '--string', type=str, help='Ciphertext string to decode')
    group.add_argument('-f', '--file', type=str, help='File containing ciphertext to decode')
    args = parser.parse_args()

    print("\nCaesar cipher brute-force decoder — shows all 26 shifts and recommends best match.")

    if args.string is not None:
        ciphertext = args.string
    elif args.file is not None:
        with open(args.file, 'r', encoding='utf-8') as f:
            ciphertext = f.read().rstrip("\n")
    else:
        ciphertext = input("\nEnter ciphertext (paste then ENTER):\n> ").rstrip("\n")

    print("\nTrying all shifts...\n")

    candidates = brute_force_all(ciphertext)

    # Show all permutations, neatly wrapped and grouped
    for i, (shift, plain, s) in enumerate(candidates, start=1):
        wrapped = textwrap.fill(plain, width=90, subsequent_indent='     ')
        print(f"Shift {shift:2d}: score={s:.6f}  ->\n     {wrapped}")
        print("─" * 75)

    # Highlight the best candidate
    best = max(candidates, key=lambda x: x[2])
    print("\nBest match:")
    print("")
    print(f" Shift {best[0]} (score={best[2]:.6f})")
    print("")
    wrapped_best = "\n  ".join(textwrap.wrap(best[1], width=78))
    print(f"  {wrapped_best}")
    if best[2] < 0.04:
        print("\nNote: score is quite low — the text may be short, contain rare words, or not be English.\n")

    print("")

if __name__ == "__main__":
    main()