"""Evaluation protocols and statistics that guard against the usual attribution-benchmark leaks.

Leave-report-out
    ATT&CK group profiles are written from the same public reports that document a campaign.
    :func:`drop_cited` removes from the graph every group ``uses`` edge whose citations are a
    subset of a held-out report set, so a case is never attributed with knowledge that only
    its own reports contributed.

Per-report cases
    :func:`report_cases` turns every (group, cited report) pair with enough techniques into a
    case: the techniques and software that one report documents for that group. With
    leave-report-out folds this gives hundreds of labelled cases from human-curated ATT&CK
    data (labels = ATT&CK's own attribution of the report to the group).

Statistics
    Exact Clopper-Pearson intervals for proportions, an exact (or Monte-Carlo) paired
    sign-flip test with Holm correction, cluster bootstrap, risk-coverage curves and a
    pool-adjacent-violators isotonic calibrator.
"""
from __future__ import annotations

import itertools
import math
import random
import re
import zlib
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import replace

from .bench import Case
from .models import Signal, SignalKind
from .sources.attack import AttackData

# ---------------------------------------------------------------- leave-report-out


def campaign_refs(attack: AttackData, cid: str) -> frozenset[str]:
    """Every citation of a campaign: the object itself, its 'uses' edges and its attribution."""
    refs = set(attack.obj_refs.get(cid, ()))
    refs |= attack.attributed_refs.get(cid, frozenset())
    for dst in attack.uses.get(cid, ()):
        refs |= attack.uses_refs.get((cid, dst), frozenset())
    return frozenset(refs)


def drop_cited(attack: AttackData, held_out: Iterable[str]) -> AttackData:
    """Copy of ``attack`` without the group 'uses' edges supported only by held-out reports.

    An edge is kept when it has no citation at all (cannot be tied to a report) or when at
    least one citation is outside ``held_out``."""
    held = frozenset(held_out)
    uses: dict[str, set[str]] = {}
    for src, dsts in attack.uses.items():
        if src not in attack.groups:
            uses[src] = dsts
            continue
        keep = {d for d in dsts
                if not (refs := attack.uses_refs.get((src, d), frozenset())) or not refs <= held}
        uses[src] = keep
    return replace(attack, uses=uses)


_YEAR = re.compile(r"(?<!\d)(19[89]\d|20[0-3]\d)(?!\d)")


def ref_year(ref: str, attack: AttackData | None = None) -> int | None:
    """Publication year of an ATT&CK citation.

    With ``attack`` the year comes from the citation's external_reference description
    ('Vendor. (2022, May 4). Title ...'), falling back to a year in the citation key such as
    'FireEye APT28 October 2014'. Many keys carry no year ('Mandiant UNC2165'), so dating
    by the key alone lets post-cutoff reports into pre-cutoff profiles."""
    if attack is not None and (y := attack.ref_years.get(ref)) is not None:
        return y
    m = _YEAR.findall(ref)
    return int(m[-1]) if m else None


def later_refs(attack: AttackData, cutoff_year: int, undated_as_later: bool = False) -> frozenset[str]:
    """Citations on any 'uses' edge dated ``cutoff_year`` or later (see :func:`ref_year`).

    ``undated_as_later`` also counts citations with no recoverable date ('n.d.' and no year in
    the key) as later - the conservative sensitivity setting."""
    out = set()
    for refs in attack.uses_refs.values():
        for r in refs:
            y = ref_year(r, attack)
            if (y is not None and y >= cutoff_year) or (y is None and undated_as_later):
                out.add(r)
    return frozenset(out)


def report_cases(attack: AttackData, min_ttps: int = 3) -> list[Case]:
    """One case per (group, cited report): the techniques/software that report documents."""
    per: dict[tuple[str, str], list[str]] = defaultdict(list)
    for (src, dst), refs in attack.uses_refs.items():
        if src not in attack.groups:
            continue
        for r in refs:
            per[(src, r)].append(dst)
    out = []
    for (gid, ref), dsts in sorted(per.items(), key=lambda kv: (attack.groups[kv[0][0]].attack_id, kv[0][1])):
        tids = sorted({attack.techniques[d].attack_id for d in dsts if d in attack.techniques})
        if len(tids) < min_ttps:
            continue
        sigs = [Signal(SignalKind.TTP, t, ref) for t in tids]
        for d in sorted(d for d in dsts if d in attack.software):
            sw = attack.software[d]
            sigs.append(Signal(SignalKind.FAMILY if sw.type == "malware" else SignalKind.TOOL, sw.name, ref))
        g = attack.groups[gid]
        cid = f"{g.attack_id}:{zlib.crc32(ref.encode()):08x}"
        out.append(Case(cid, ref, sigs, {g.name},
                        {"group": g.name, "group_id": gid, "report": ref, "year": ref_year(ref, attack),
                         "n_ttp": len(tids), "n_software": len(sigs) - len(tids)}))
    return out


def fold_of(report: str, k: int, seed: int = 0) -> int:
    return zlib.crc32(f"{seed}:{report}".encode()) % k


# ---------------------------------------------------------------- statistics


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact binomial CI for k successes in n trials (bisection on the binomial tail)."""
    if n == 0:
        return (float("nan"), float("nan"))

    def upper_tail(p: float) -> float:        # P(X >= k), increasing in p
        return 1.0 - sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k))

    def lower_tail(p: float) -> float:        # P(X <= k), decreasing in p
        return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))

    def bisect(f: Callable[[float], float], increasing: bool) -> float:
        lo, hi = 0.0, 1.0
        for _ in range(60):
            mid = (lo + hi) / 2
            if (f(mid) < alpha / 2) == increasing:
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else bisect(upper_tail, True)
    upper = 1.0 if k == n else bisect(lower_tail, False)
    return (lower, upper)


N_MC = 200_000


def sign_flip_test(diffs: list[float], n_mc: int = N_MC, seed: int = 0) -> dict:
    """Paired permutation (sign-flip) test of mean(diffs) > 0.

    Exact enumeration when at most 20 differences are non-zero. Otherwise Monte Carlo with
    ``n_mc`` random sign vectors, reported as the valid permutation p-value (k + 1) / (B + 1),
    where k counts sign vectors at least as extreme (so it is never 0; the smallest value is
    1 / (B + 1)). Returns one- and two-sided p-values, the number of discordant pairs, ``exact``
    and, for Monte Carlo, ``n_mc`` (B) and the exceedance counts."""
    nz = [d for d in diffs if d != 0]
    obs = sum(nz)
    if not nz:
        return {"n_discordant": 0, "p_one_sided": 1.0, "p_two_sided": 1.0, "exact": True, "n_mc": None}
    ge = absge = tot = 0
    if len(nz) <= 20:
        for signs in itertools.product((1, -1), repeat=len(nz)):
            s = sum(a * b for a, b in zip(signs, nz))
            ge += s >= obs - 1e-12
            absge += abs(s) >= abs(obs) - 1e-12
            tot += 1
        return {"n_discordant": len(nz), "p_one_sided": ge / tot, "p_two_sided": absge / tot,
                "exact": True, "n_mc": None}
    rng = random.Random(seed)
    for _ in range(n_mc):
        s = sum(d if rng.random() < 0.5 else -d for d in nz)
        ge += s >= obs - 1e-12
        absge += abs(s) >= abs(obs) - 1e-12
    return {"n_discordant": len(nz), "p_one_sided": (ge + 1) / (n_mc + 1),
            "p_two_sided": (absge + 1) / (n_mc + 1), "exact": False, "n_mc": n_mc,
            "k_one_sided": ge, "k_two_sided": absge}


def cluster_sign_flip_test(diffs: list[float], clusters: list[str], n_mc: int = N_MC, seed: int = 0) -> dict:
    """Sign-flip test that respects clustering: the per-case differences are summed within each
    cluster (e.g. threat group) and whole clusters are sign-flipped, so cases of one group are
    not treated as independent. Same p-value conventions as :func:`sign_flip_test`."""
    sums: dict[str, float] = defaultdict(float)
    for d, c in zip(diffs, clusters):
        sums[c] += d
    r = sign_flip_test([sums[c] for c in sorted(sums)], n_mc=n_mc, seed=seed)
    r["n_clusters"] = len(sums)
    r["n_discordant_clusters"] = r.pop("n_discordant")
    r["n_discordant"] = sum(1 for d in diffs if d != 0)
    return r


def holm(pvals: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni adjusted p-values (family-wise error control)."""
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items)
    out, running = {}, 0.0
    for i, (k, p) in enumerate(items):
        running = max(running, min(1.0, (m - i) * p))
        out[k] = running
    return out


def cluster_bootstrap(rows: list[dict], cluster: Callable[[dict], str], stat: Callable[[list[dict]], float],
                      n_boot: int = 2000, seed: int = 0, alpha: float = 0.05) -> tuple[float, float]:
    """Percentile CI of ``stat`` resampling whole clusters (groups, families, imphashes)."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups[cluster(r)].append(r)
    keys = sorted(groups)
    if not keys:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    vals = []
    for _ in range(n_boot):
        smp = [r for _ in keys for r in groups[keys[rng.randrange(len(keys))]]]
        v = stat(smp)
        if not math.isnan(v):
            vals.append(v)
    vals.sort()
    if not vals:
        return (float("nan"), float("nan"))
    return (vals[int(alpha / 2 * (len(vals) - 1))], vals[int((1 - alpha / 2) * (len(vals) - 1))])


def risk_coverage(conf_ok: list[tuple[float, float]], points=(0.2, 0.4, 0.6, 0.8, 1.0)) -> dict:
    """Selective risk (error rate among the most confident cases) at fixed coverage, and the
    area under the risk-coverage curve. Ties in confidence are resolved in expectation."""
    n = len(conf_ok)
    if not n:
        return {"aurc": float("nan"), "risk_at": {}}
    by: dict[float, list[float]] = defaultdict(list)
    for c, ok in conf_ok:
        by[c].append(float(ok))
    groups = [by[c] for c in sorted(by, reverse=True)]
    # expected cumulative errors after taking the first m cases, m = 1..n
    cum_err, taken, err = [0.0], 0, 0.0
    for g in groups:
        rate = 1.0 - sum(g) / len(g)
        for _ in g:
            taken += 1
            err += rate
            cum_err.append(err)
    risk = {f"{p:.1f}": cum_err[max(1, round(p * n))] / max(1, round(p * n)) for p in points}
    aurc = sum(cum_err[m] / m for m in range(1, n + 1)) / n
    return {"aurc": aurc, "risk_at": risk}


class Isotonic:
    """Pool-adjacent-violators isotonic regression: monotone map score -> probability."""

    def __init__(self) -> None:
        self.x: list[float] = []
        self.y: list[float] = []

    def fit(self, xs: list[float], ys: list[float]) -> Isotonic:
        pts = sorted(zip(xs, ys))
        blocks: list[list[float]] = []          # [sum_y, count, max_x]
        for x, y in pts:
            blocks.append([y, 1, x])
            while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
                s, c, mx = blocks.pop()
                blocks[-1][0] += s
                blocks[-1][1] += c
                blocks[-1][2] = mx
        self.x = [b[2] for b in blocks]
        self.y = [b[0] / b[1] for b in blocks]
        return self

    def __call__(self, x: float) -> float:
        if not self.x:
            return x
        for bx, by in zip(self.x, self.y):
            if x <= bx:
                return by
        return self.y[-1]
