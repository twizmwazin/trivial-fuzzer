use libafl::monitors::{ClientStats, Monitor};
use libafl_bolts::{current_time, ClientId};
use serde::Serialize;
use std::{fmt, time::Duration};

#[derive(Clone)]
pub struct JsonMonitor<F>
where
    F: FnMut(&JsonMonitorOutput),
{
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    print_fn: F,
}

impl<F> JsonMonitor<F>
where
    F: FnMut(&JsonMonitorOutput),
{
    pub fn new(print_fn: F) -> Self {
        Self {
            start_time: current_time(),
            client_stats: Vec::new(),
            print_fn,
        }
    }
}

impl<F> fmt::Debug for JsonMonitor<F>
where
    F: FnMut(&JsonMonitorOutput),
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonMonitor")
            .field("start_time", &self.start_time)
            .field("client_stats", &self.client_stats)
            .finish_non_exhaustive()
    }
}

impl<F> Monitor for JsonMonitor<F>
where
    F: FnMut(&JsonMonitorOutput),
{
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    fn display(&mut self, event_msg: String, sender_id: ClientId) {
        let output = JsonMonitorOutput {
            event_msg,
            sender_id,
            duration: (current_time() - self.start_time).as_millis(),
            clients: self.client_stats().len(),
            corpus: self.corpus_size(),
            objectives: self.objective_size(),
            executions: self.total_execs(),
            execs_per_sec: self.execs_per_sec(),
        };
        (self.print_fn)(&output)
    }
}

#[derive(Serialize)]
pub struct JsonMonitorOutput {
    pub event_msg: String,
    pub sender_id: ClientId,
    pub duration: u128,
    pub clients: usize,
    pub corpus: u64,
    pub objectives: u64,
    pub executions: u64,
    pub execs_per_sec: f64,
}
