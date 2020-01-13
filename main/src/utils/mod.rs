use histogram::Histogram;
use log::info;

pub fn display_histogram(prefix: &str, histogram: Histogram) {
    // print percentiles from the histogram
    info!(
        "({}) Percentiles: <0.1%: {} ticks, <1.0%: {} ticks, \
         <10% {} ticks, <%50% {} ticks, <90% {} ticks, \
         p99: {} ticks, p99.9: {} ticks",
        prefix,
        histogram.percentile(0.1).unwrap(),
        histogram.percentile(1.0).unwrap(),
        histogram.percentile(10.0).unwrap(),
        histogram.percentile(50.0).unwrap(),
        histogram.percentile(90.0).unwrap(),
        histogram.percentile(99.0).unwrap(),
        histogram.percentile(99.9).unwrap(),
    );

    // print additional statistics
    info!(
        "({}) Latency (ticks): Min: {} Avg: {} Max: {} StdDev: {}",
        prefix,
        histogram.minimum().unwrap(),
        histogram.mean().unwrap(),
        histogram.maximum().unwrap(),
        histogram.stddev().unwrap(),
    );
}
