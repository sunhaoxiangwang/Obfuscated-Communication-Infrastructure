//! SCF Client Binary
//!
//! Usage: scf-client [OPTIONS]
//!
//! Options:
//!   -c, --config <FILE>  Path to configuration file
//!   -t, --test           Test connection to server
//!   -h, --help           Print help information

use std::env;

use scf::reality::{RealityClient, RealityConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        "-h" | "--help" => {
            print_usage();
        }
        "-t" | "--test" => {
            if args.len() < 3 {
                eprintln!("Error: --test requires a config file path");
                return Ok(());
            }
            test_connection(&args[2]).await?;
        }
        "-c" | "--config" => {
            if args.len() < 3 {
                eprintln!("Error: --config requires a file path");
                return Ok(());
            }
            run_client(&args[2]).await?;
        }
        _ => {
            eprintln!("Unknown option: {}", args[1]);
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!(
        r#"SCF Client - Steganographic Communication Framework

USAGE:
    scf-client [OPTIONS]

OPTIONS:
    -c, --config <FILE>  Path to configuration file
    -t, --test <FILE>    Test connection using config file
    -h, --help           Print help information

CONFIGURATION FILE FORMAT (JSON):
    {{
        "server_public_key": "<base64>",
        "short_id": "<hex>",
        "cover_sni": "www.example.com",
        "server_addr": "server.example.com",
        "server_port": 443
    }}

EXAMPLES:
    Test connection:
        scf-client --test client.json

    Run interactive client:
        scf-client --config client.json
"#
    );
}

async fn test_connection(config_path: &str) -> anyhow::Result<()> {
    let config = load_config(config_path)?;

    tracing::info!("Testing connection to {}:{}", config.server_addr, config.server_port);
    tracing::info!("Cover SNI: {}", config.cover_sni);

    let client = RealityClient::new(config)?;

    match client.connect().await {
        Ok(mut conn) => {
            tracing::info!("Connection established successfully!");

            // Send test message
            conn.send(b"Hello, SCF!").await?;
            tracing::info!("Sent test message");

            // Try to receive response
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                conn.recv(),
            )
            .await
            {
                Ok(Ok(data)) => {
                    tracing::info!("Received response: {} bytes", data.len());
                }
                Ok(Err(e)) => {
                    tracing::warn!("Receive error: {}", e);
                }
                Err(_) => {
                    tracing::info!("No response within timeout (this may be normal)");
                }
            }

            conn.close().await?;
            tracing::info!("Connection closed successfully");
        }
        Err(e) => {
            tracing::error!("Connection failed: {}", e);
        }
    }

    Ok(())
}

async fn run_client(config_path: &str) -> anyhow::Result<()> {
    let config = load_config(config_path)?;

    tracing::info!("Connecting to {}:{}", config.server_addr, config.server_port);

    let client = RealityClient::new(config)?;
    let mut conn = client.connect().await?;

    tracing::info!("Connected. Type messages to send, Ctrl+C to exit.");

    // Simple echo client
    let mut input = String::new();
    loop {
        input.clear();
        std::io::stdin().read_line(&mut input)?;

        let msg = input.trim();
        if msg.is_empty() {
            continue;
        }

        conn.send(msg.as_bytes()).await?;

        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.recv(),
        )
        .await
        {
            Ok(Ok(data)) => {
                if let Ok(text) = String::from_utf8(data) {
                    println!("< {}", text);
                } else {
                    println!("< [binary data]");
                }
            }
            Ok(Err(e)) => {
                eprintln!("Error: {}", e);
                break;
            }
            Err(_) => {
                // Timeout is okay for some applications
            }
        }
    }

    conn.close().await?;
    Ok(())
}

fn load_config(path: &str) -> anyhow::Result<RealityConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: RealityConfig = serde_json::from_str(&content)?;
    config.validate().map_err(|e| anyhow::anyhow!(e))?;
    Ok(config)
}
