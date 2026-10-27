using System.Globalization;

namespace Stenwatch.Core;

/// <summary>Operational measures from the remediation tasks (pillar 15). Counts only what the data supports:
/// a task that was never verified has no time-to-remediate, and is reported as unverified instead of being averaged in.</summary>
public record OpsMetrics(int Opened, int Verified, int Unverified, int Active, int Overdue, double? MedianDaysToVerify, double? SlaCompliance, double? VerifiedClosureRate,
                         Dictionary<string, double?> MedianDaysByTier);

public static class Effectiveness
{
    static DateOnly P(string s) => DateOnly.ParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture);

    static double? Median(IEnumerable<double> xs)
    {
        var l = xs.Order().ToList();
        return l.Count == 0 ? null : l.Count % 2 == 1 ? l[l.Count / 2] : (l[l.Count / 2 - 1] + l[l.Count / 2]) / 2;
    }

    /// <summary>MTTR, SLA compliance and verified-closure rate. SLA compliance = verified on or before the due date, among verified tasks.
    /// Verified-closure rate = verified / (verified + claimed fixed but not confirmed), i.e. how often "done" survives a re-scan.</summary>
    public static OpsMetrics Ops(IReadOnlyList<RemediationTask> tasks, DateOnly today)
    {
        var verified = tasks.Where(t => t.State == TaskState.Verified && t.Closed != "").ToList();
        var days = verified.Select(t => (double)(P(t.Closed).DayNumber - P(t.Opened).DayNumber)).ToList();
        var inSla = verified.Count(t => string.CompareOrdinal(t.Closed, t.Due) <= 0);
        // a fix claim that did not hold: the next scan still found it (the note stays when the task is picked up again)
        var claims = tasks.Count(t => t.Note.StartsWith("claimed fixed, but"));
        return new OpsMetrics(tasks.Count, verified.Count, tasks.Count(t => t.State == TaskState.Fixed),
            tasks.Count(t => TaskState.Active.Contains(t.State)), tasks.Count(t => t.Overdue(today)), Median(days),
            verified.Count == 0 ? null : (double)inSla / verified.Count,
            verified.Count + claims == 0 ? null : (double)verified.Count / (verified.Count + claims),
            verified.GroupBy(t => t.Tier).ToDictionary(g => g.Key, g => Median(g.Select(t => (double)(P(t.Closed).DayNumber - P(t.Opened).DayNumber)))));
    }
}

/// <summary>One CVE (or finding) as it looked at prediction time, with whether the outcome happened afterwards.
/// Features must only contain information available at that time; the data loader is responsible for that.</summary>
public record Candidate(string Id, bool Positive, Dictionary<string, double> X);

public record RankingScores(string Name, double AveragePrecision, Dictionary<int, (double Coverage, double Efficiency, double Effort)> AtN, double? Brier);

/// <summary>EPSS-style evaluation: exploitation is rare, so accuracy misleads. Coverage = share of all positives found in the top N,
/// efficiency = share of the top N that are positives, effort = share of the population you had to act on.</summary>
public static class Metrics
{
    /// <summary>Candidate order by score, highest first. Ties are broken pseudo-randomly (seeded), so a scorer cannot win by tie luck.</summary>
    static List<Candidate> Order(IReadOnlyList<Candidate> c, Func<Candidate, double> score, int seed)
    {
        var rnd = new Random(seed);
        return c.Select(x => (x, s: score(x), t: rnd.NextDouble())).OrderByDescending(x => x.s).ThenBy(x => x.t).Select(x => x.x).ToList();
    }

    public static double AveragePrecision(IReadOnlyList<Candidate> c, Func<Candidate, double> score, int seeds = 20)
    {
        int pos = c.Count(x => x.Positive);
        if (pos == 0) return 0;
        double total = 0;
        for (int s = 0; s < seeds; s++)
        {
            int tp = 0; double ap = 0; var o = Order(c, score, s);
            for (int i = 0; i < o.Count; i++) if (o[i].Positive) { tp++; ap += (double)tp / (i + 1); }
            total += ap / pos;
        }
        return total / seeds;
    }

    public static (double Coverage, double Efficiency, double Effort) AtTop(IReadOnlyList<Candidate> c, Func<Candidate, double> score, int n, int seeds = 20)
    {
        int pos = c.Count(x => x.Positive); n = Math.Min(n, c.Count);
        double tp = 0;
        for (int s = 0; s < seeds; s++) tp += Order(c, score, s).Take(n).Count(x => x.Positive);
        tp /= seeds;
        return (pos == 0 ? 0 : tp / pos, n == 0 ? 0 : tp / n, c.Count == 0 ? 0 : (double)n / c.Count);
    }

    /// <summary>Mean squared error of a probability against the outcome; lower is better, 0.25 is a coin flip at base rate 0.5.</summary>
    public static double Brier(IReadOnlyList<Candidate> c, Func<Candidate, double> probability) =>
        c.Average(x => Math.Pow(Math.Clamp(probability(x), 0, 1) - (x.Positive ? 1 : 0), 2));

    public static RankingScores Evaluate(IReadOnlyList<Candidate> c, string name, Func<Candidate, double> score, IEnumerable<int> topN, bool isProbability = false) =>
        new(name, AveragePrecision(c, score), topN.ToDictionary(n => n, n => AtTop(c, score, n)), isProbability ? Brier(c, score) : null);

    /// <summary>Paired bootstrap of the average-precision difference A - B over resampled candidates (fixed seed, so reruns agree).
    /// -> (observed difference, 95% interval low, high, share of resamples where A did not beat B).</summary>
    public static (double Delta, double Low, double High, double PNotBetter) PairedBootstrap(IReadOnlyList<Candidate> c, Func<Candidate, double> a,
                                                                                            Func<Candidate, double> b, int resamples = 1000, int seed = 7)
    {
        var rnd = new Random(seed); var deltas = new List<double>();
        double observed = AveragePrecision(c, a, 5) - AveragePrecision(c, b, 5);
        for (int i = 0; i < resamples; i++)
        {
            var sample = Enumerable.Range(0, c.Count).Select(_ => c[rnd.Next(c.Count)]).ToList();
            if (!sample.Any(x => x.Positive)) { i--; continue; }
            deltas.Add(AveragePrecision(sample, a, 2) - AveragePrecision(sample, b, 2));
        }
        deltas.Sort();
        return (observed, deltas[(int)(0.025 * deltas.Count)], deltas[(int)(0.975 * deltas.Count) - 1], deltas.Count(d => d <= 0) / (double)deltas.Count);
    }

    // ---- array versions for large populations (hundreds of thousands of CVEs) ----

    static int[] OrderIdx(double[] score, int seed)
    {
        var rnd = new Random(seed); var tie = new double[score.Length];
        for (int i = 0; i < tie.Length; i++) tie[i] = rnd.NextDouble();
        var idx = Enumerable.Range(0, score.Length).ToArray();
        Array.Sort(idx, (a, b) => score[a] != score[b] ? score[b].CompareTo(score[a]) : tie[a].CompareTo(tie[b]));
        return idx;
    }

    public static double AveragePrecision(bool[] pos, double[] score, int seeds = 5)
    {
        int total = pos.Count(x => x); if (total == 0) return 0; double sum = 0;
        for (int s = 0; s < seeds; s++)
        {
            int tp = 0, rank = 0; double ap = 0;
            foreach (var i in OrderIdx(score, s)) { rank++; if (pos[i]) { tp++; ap += (double)tp / rank; } }
            sum += ap / total;
        }
        return sum / seeds;
    }

    public static (double Coverage, double Efficiency, double Effort) AtTop(bool[] pos, double[] score, int n, int seeds = 5)
    {
        int total = pos.Count(x => x); n = Math.Min(n, pos.Length); double tp = 0;
        for (int s = 0; s < seeds; s++) tp += OrderIdx(score, s).Take(n).Count(i => pos[i]);
        tp /= seeds;
        return (total == 0 ? 0 : tp / total, n == 0 ? 0 : tp / n, (double)n / pos.Length);
    }

    /// <summary>Paired bootstrap of the average-precision difference A - B. Each resample reweights the items instead of re-sorting them
    /// (one fixed tie-break order per ranking), so hundreds of thousands of candidates stay fast.</summary>
    public static (double Delta, double Low, double High, double PNotBetter) PairedBootstrap(bool[] pos, double[] a, double[] b, int resamples = 1000, int seed = 7)
    {
        var oa = OrderIdx(a, 1); var ob = OrderIdx(b, 1); var rnd = new Random(seed); var counts = new int[pos.Length];
        double Ap(int[] order)
        {
            long rank = 0; long tp = 0; double ap = 0; long total = 0;
            foreach (var i in order) if (pos[i]) total += counts[i];
            if (total == 0) return double.NaN;
            foreach (var i in order)
            {
                int w = counts[i]; if (w == 0) continue;
                if (pos[i]) { for (int k = 1; k <= w; k++) ap += (double)(tp + k) / (rank + k); tp += w; }
                rank += w;
            }
            return ap / total;
        }
        for (int i = 0; i < counts.Length; i++) counts[i] = 1;
        double observed = Ap(oa) - Ap(ob);
        var deltas = new List<double>();
        while (deltas.Count < resamples)
        {
            Array.Clear(counts);
            for (int i = 0; i < pos.Length; i++) counts[rnd.Next(pos.Length)]++;
            double d = Ap(oa) - Ap(ob);
            if (!double.IsNaN(d)) deltas.Add(d);
        }
        deltas.Sort();
        return (observed, deltas[(int)(0.025 * deltas.Count)], deltas[(int)(0.975 * deltas.Count) - 1], deltas.Count(d => d <= 0) / (double)deltas.Count);
    }
}
