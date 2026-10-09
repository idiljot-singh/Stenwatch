"""Unit tests for the statistics in tools/backtest.py, on tiny examples whose answers can be worked out by hand.  python tools/test_backtest.py"""
import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backtest import auc, hits_at, reviews_for, sign_test, tie_groups, wilson

# six items in three tie groups of two: scores 3,3 | 2,2 | 1,1; positives: one in group 1, one in group 2
score = np.array([3, 3, 2, 2, 1, 1], float)
y = np.array([1, 0, 0, 1, 0, 0], float)
g = tie_groups(score, y)
assert list(g[0]) == [2, 4, 6] and list(g[1]) == [1, 2, 2], g
# expected positives found after k reviews, ties in random order
assert hits_at(g, 1) == 0.5 and hits_at(g, 2) == 1.0 and hits_at(g, 3) == 1.5 and hits_at(g, 6) == 2.0 and hits_at(g, 0) == 0
# expected reviews needed to find 1, 1.5 and 2 positives
assert reviews_for(g, 1.0) == 2.0 and reviews_for(g, 1.5) == 3.0 and reviews_for(g, 2.0) == 4.0
# AUC with half credit for ties. Positive in group 1: beats the 3 negatives scored lower and ties 1 => 3.5. Positive in group 2: beats 2 and ties 1 => 2.5.
# (3.5 + 2.5) / (2 positives x 4 negatives) = 0.75
assert abs(auc(g) - 0.75) < 1e-12
# a perfect ranking has AUC 1, a ranking with no information (all tied) has AUC 0.5, a worst-case ranking has AUC 0
assert auc(tie_groups(np.array([4, 3, 2, 1], float), np.array([1, 1, 0, 0], float))) == 1.0
assert abs(auc(tie_groups(np.ones(10), np.array([1, 0] * 5, float))) - 0.5) < 1e-12
assert auc(tie_groups(np.array([1, 2, 3, 4], float), np.array([1, 1, 0, 0], float))) == 0.0
# Wilson interval: known value for 8/10 and the boundary cases
lo, hi = wilson(8, 10)
assert abs(lo - 0.4902) < 1e-3 and abs(hi - 0.9433) < 1e-3, (lo, hi)
assert wilson(0, 10)[0] == 0.0 and wilson(10, 10)[1] == 1.0 and wilson(0, 0) == (0.0, 1.0)
# exact sign test: 5 vs 5 is no evidence, 10 vs 0 is p = 2 * 0.5^10, 9 vs 1 has p = 2 * 11 / 1024
assert sign_test(5, 5) == 1.0 and sign_test(0, 0) == 1.0
assert math.isclose(sign_test(10, 0), 2 / 1024) and math.isclose(sign_test(9, 1), 22 / 1024)
print("ok")
