use clap::{Parser, Subcommand};
use gossip_rs::crds::Keypair;
use gossip_rs::node::{Config, GOSSIP_INTERVAL_MS, Node};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

// nodes the local demo starts when --nodes is not given
const DEMO_NODES: usize = 5;

// how long the demo waits for convergence before giving up
const DEMO_TIMEOUT_SECS: u64 = 30;

// how often the demo checks whether the nodes agree
const CONVERGENCE_POLL: Duration = Duration::from_millis(10);

// how often a running node logs its view of the cluster
const STATUS_INTERVAL: Duration = Duration::from_secs(5);

// values each demo node ends up holding per node in the cluster: a contact info and a vote
const VALUES_PER_NODE: usize = 2;

#[derive(Parser)]
#[command(name = "gossip-rs", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// run one gossip node
    Node {
        /// address to bind and advertise, e.g. 127.0.0.1:8001
        #[arg(long)]
        bind: SocketAddr,
        /// any node already in the cluster
        #[arg(long)]
        entrypoint: Option<SocketAddr>,
        /// solana-format keypair file; a fresh identity is used when omitted
        #[arg(long)]
        keypair: Option<PathBuf>,
        /// push interval in milliseconds; pull runs every 5 intervals
        #[arg(long, default_value_t = GOSSIP_INTERVAL_MS)]
        interval_ms: u64,
        /// publish a vote for the next slot this often
        #[arg(long)]
        vote_interval_ms: Option<u64>,
    },
    /// start several nodes on localhost and report how long they take to converge
    Demo {
        #[arg(long, default_value_t = DEMO_NODES)]
        nodes: usize,
        #[arg(long, default_value_t = GOSSIP_INTERVAL_MS)]
        interval_ms: u64,
        #[arg(long, default_value_t = DEMO_TIMEOUT_SECS)]
        timeout_secs: u64,
    },
    /// write a new solana-format keypair file
    Keygen {
        #[arg(long)]
        outfile: PathBuf,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let result = match Cli::parse().command {
        Command::Node {
            bind,
            entrypoint,
            keypair,
            interval_ms,
            vote_interval_ms,
        } => run_node(bind, entrypoint, keypair, interval_ms, vote_interval_ms),
        Command::Demo {
            nodes,
            interval_ms,
            timeout_secs,
        } => run_demo(nodes, interval_ms, timeout_secs),
        Command::Keygen { outfile } => {
            let keypair = Keypair::new();
            keypair
                .write_file(&outfile)
                .map(|()| println!("{}", keypair.pubkey()))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run_node(
    bind: SocketAddr,
    entrypoint: Option<SocketAddr>,
    keypair: Option<PathBuf>,
    interval_ms: u64,
    vote_interval_ms: Option<u64>,
) -> Result<(), String> {
    let keypair = match keypair {
        Some(path) => Keypair::read_file(&path)?,
        None => Keypair::new(),
    };
    let node = Node::start(
        Config::new(bind, entrypoint, Duration::from_millis(interval_ms)),
        keypair,
    )
    .map_err(|e| e.to_string())?;
    let mut slot = 0;
    let mut last_vote = Instant::now();
    let mut last_status = Instant::now();
    loop {
        if let Some(every) = vote_interval_ms
            && last_vote.elapsed() >= Duration::from_millis(every)
        {
            slot += 1;
            if let Err(e) = node.publish_vote(slot) {
                tracing::warn!("vote for slot {slot} rejected: {e:?}");
            }
            last_vote = Instant::now();
        }
        if last_status.elapsed() >= STATUS_INTERVAL {
            let m = node.metrics();
            tracing::info!(
                peers = node.peers().len(),
                values = node.num_values(),
                packets_sent = m.packets_sent,
                packets_received = m.packets_received,
                prunes_sent = m.prunes_sent,
                "status"
            );
            last_status = Instant::now();
        }
        thread::sleep(CONVERGENCE_POLL);
    }
}

fn run_demo(count: usize, interval_ms: u64, timeout_secs: u64) -> Result<(), String> {
    if count == 0 {
        return Err("--nodes must be at least 1".into());
    }
    let interval = Duration::from_millis(interval_ms);
    let localhost: SocketAddr = ([127, 0, 0, 1], 0).into();
    let started = Instant::now();
    let first = Node::start(Config::new(localhost, None, interval), Keypair::new())
        .map_err(|e| e.to_string())?;
    let entrypoint = first.gossip_addr();
    let mut nodes = vec![first];
    for _ in 1..count {
        nodes.push(
            Node::start(
                Config::new(localhost, Some(entrypoint), interval),
                Keypair::new(),
            )
            .map_err(|e| e.to_string())?,
        );
    }
    for (slot, node) in nodes.iter().enumerate() {
        node.publish_vote(slot as u64)
            .map_err(|e| format!("{e:?}"))?;
    }
    let deadline = started + Duration::from_secs(timeout_secs);
    loop {
        let first_table = nodes[0].table();
        if first_table.len() == count * VALUES_PER_NODE
            && nodes.iter().all(|n| n.table() == first_table)
        {
            break;
        }
        if Instant::now() > deadline {
            return Err(format!("no convergence within {timeout_secs}s"));
        }
        thread::sleep(CONVERGENCE_POLL);
    }
    let elapsed = started.elapsed();
    let max_packet = nodes
        .iter()
        .map(|n| n.metrics().max_packet_bytes)
        .max()
        .unwrap_or(0);
    let packets: u64 = nodes.iter().map(|n| n.metrics().packets_sent).sum();
    println!(
        "{count} nodes converged on {} values in {} ms; {packets} packets sent, largest {max_packet} bytes",
        count * VALUES_PER_NODE,
        elapsed.as_millis()
    );
    for node in nodes {
        node.shutdown();
    }
    Ok(())
}
