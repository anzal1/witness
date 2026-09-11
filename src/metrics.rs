//! Process-local counters, rendered as Prometheus text exposition by hand.
//! No client library: the exposition format is a dozen lines of text and the
//! dependency tree stays as small as the rest of the binary.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Upper bounds in seconds. A proxied call is either sub-millisecond (cache
/// hit, journal append) or as slow as inference, so the buckets span from
/// half a millisecond to half a minute.
pub const BUCKETS: [f64; 15] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

#[derive(Default)]
pub struct Metrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub replays: AtomicU64,
    /// Fleet mode: requests answered out of a sibling instance's cache.
    pub peer_hits: AtomicU64,
    /// Peer lookups that failed rather than cleanly missed.
    pub peer_errors: AtomicU64,
    pub signed: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub otlp_exported: AtomicU64,
    pub otlp_dropped: AtomicU64,
    /// Cumulative bucket counts, parallel to `BUCKETS`. The +Inf bucket is
    /// `count`, so it is not stored separately.
    buckets: [AtomicU64; BUCKETS.len()],
    /// Observed seconds, kept in microseconds to stay in integer atomics.
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Metrics {
    pub fn observe(&self, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        for (i, bound) in BUCKETS.iter().enumerate() {
            if secs <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sum_micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus text exposition format, version 0.0.4.
    pub fn render(&self, journal_records: u64) -> String {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let mut out = String::with_capacity(1024);

        out.push_str("# HELP witness_requests_total Proxied requests by cache disposition.\n");
        out.push_str("# TYPE witness_requests_total counter\n");
        out.push_str(&format!(
            "witness_requests_total{{cache=\"hit\"}} {}\n",
            g(&self.hits)
        ));
        out.push_str(&format!(
            "witness_requests_total{{cache=\"miss\"}} {}\n",
            g(&self.misses)
        ));
        out.push_str(&format!(
            "witness_requests_total{{cache=\"replay\"}} {}\n",
            g(&self.replays)
        ));
        // A peer hit is exactly one request served, so one counter renders
        // under two names. The label keeps `witness_requests_total` summing to
        // the request total; the dedicated series below keeps fleet traffic
        // readable on a dashboard without a label join.
        out.push_str(&format!(
            "witness_requests_total{{cache=\"peer\"}} {}\n",
            g(&self.peer_hits)
        ));

        out.push_str(
            "# HELP witness_requests_signed_total Requests carrying a verified Pact signature.\n",
        );
        out.push_str("# TYPE witness_requests_signed_total counter\n");
        out.push_str(&format!(
            "witness_requests_signed_total {}\n",
            g(&self.signed)
        ));

        out.push_str("# HELP witness_journal_records Records in the hash-chained journal.\n");
        out.push_str("# TYPE witness_journal_records gauge\n");
        out.push_str(&format!("witness_journal_records {journal_records}\n"));

        out.push_str("# HELP witness_upstream_errors_total Upstream calls that never completed: transport failures, unreadable bodies, truncated streams.\n");
        out.push_str("# TYPE witness_upstream_errors_total counter\n");
        out.push_str(&format!(
            "witness_upstream_errors_total {}\n",
            g(&self.upstream_errors)
        ));

        out.push_str(
            "# HELP witness_peer_hits_total Requests answered from a sibling instance's cache instead of the upstream.\n",
        );
        out.push_str("# TYPE witness_peer_hits_total counter\n");
        out.push_str(&format!("witness_peer_hits_total {}\n", g(&self.peer_hits)));

        out.push_str("# HELP witness_peer_errors_total Peer lookups that failed rather than cleanly missed: unreachable, unauthorized, over budget, or a body that did not match its advertised hash.\n");
        out.push_str("# TYPE witness_peer_errors_total counter\n");
        out.push_str(&format!(
            "witness_peer_errors_total {}\n",
            g(&self.peer_errors)
        ));

        out.push_str(
            "# HELP witness_otlp_spans_exported_total GenAI spans accepted by the OTLP endpoint.\n",
        );
        out.push_str("# TYPE witness_otlp_spans_exported_total counter\n");
        out.push_str(&format!(
            "witness_otlp_spans_exported_total {}\n",
            g(&self.otlp_exported)
        ));

        out.push_str("# HELP witness_otlp_spans_dropped_total GenAI spans discarded: queue backpressure or a failed export.\n");
        out.push_str("# TYPE witness_otlp_spans_dropped_total counter\n");
        out.push_str(&format!(
            "witness_otlp_spans_dropped_total {}\n",
            g(&self.otlp_dropped)
        ));

        out.push_str(
            "# HELP witness_request_duration_seconds Time spent handling a proxied request.\n",
        );
        out.push_str("# TYPE witness_request_duration_seconds histogram\n");
        for (i, bound) in BUCKETS.iter().enumerate() {
            out.push_str(&format!(
                "witness_request_duration_seconds_bucket{{le=\"{bound}\"}} {}\n",
                g(&self.buckets[i])
            ));
        }
        let count = g(&self.count);
        out.push_str(&format!(
            "witness_request_duration_seconds_bucket{{le=\"+Inf\"}} {count}\n"
        ));
        out.push_str(&format!(
            "witness_request_duration_seconds_sum {:.6}\n",
            g(&self.sum_micros) as f64 / 1_000_000.0
        ));
        out.push_str(&format!("witness_request_duration_seconds_count {count}\n"));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_cumulative_and_monotonic() {
        let m = Metrics::default();
        m.observe(Duration::from_micros(200)); // <= every bucket
        m.observe(Duration::from_secs(2)); // <= 2.5 and up
        let text = m.render(7);
        assert!(text.contains("witness_request_duration_seconds_bucket{le=\"0.0005\"} 1"));
        assert!(text.contains("witness_request_duration_seconds_bucket{le=\"1\"} 1"));
        assert!(text.contains("witness_request_duration_seconds_bucket{le=\"2.5\"} 2"));
        assert!(text.contains("witness_request_duration_seconds_bucket{le=\"+Inf\"} 2"));
        assert!(text.contains("witness_request_duration_seconds_count 2"));
        assert!(text.contains("witness_journal_records 7"));
    }

    #[test]
    fn every_series_is_declared_before_it_is_used() {
        let text = Metrics::default().render(0);
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let name = line.split(['{', ' ']).next().unwrap();
            let family = name
                .strip_suffix("_bucket")
                .or_else(|| name.strip_suffix("_sum"))
                .or_else(|| name.strip_suffix("_count"))
                .unwrap_or(name);
            assert!(
                text.contains(&format!("# TYPE {family} ")),
                "{name} has no TYPE line"
            );
        }
    }
}
