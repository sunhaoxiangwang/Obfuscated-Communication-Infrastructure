//! SCF Server Binary
//!
//! Usage: scf-server [OPTIONS]
//!
//! Options:
//!   -c, --config <FILE>  Path to configuration file
//!   -g, --generate       Generate new server configuration
//!   -h, --help           Print help information

use std::env;
use std::path::PathBuf;

use scf::server::{Server, ServerConfig};

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
        "-g" | "--generate" => {
            generate_config()?;
        }
        "-c" | "--config" => {
            if args.len() < 3 {
                eprintln!("Error: --config requires a file path");
                return Ok(());
            }
            run_server(&args[2]).await?;
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
        r#"SCF Server - Steganographic Communication Framework

USAGE:
    scf-server [OPTIONS]

OPTIONS:
    -c, --config <FILE>  Path to configuration file
    -g, --generate       Generate new server configuration
    -h, --help           Print help information

EXAMPLES:
    Generate a new configuration:
        scf-server --generate > server.toml

    Run the server:
        scf-server --config server.toml
"#
    );
}

fn generate_config() -> anyhow::Result<()> {
    use scf::server::config::ServerConfigFile;

    let mut config = ServerConfig::new_random("0.0.0.0", 443, "www.microsoft.com");
    let short_id = config.generate_short_id();

    let config_file = ServerConfigFile::from_config(&config);

    println!("# SCF Server Configuration");
    println!("# Generated: {}", chrono::Utc::now());
    println!();
    println!("{}", toml::to_string_pretty(&config_file)?);
    println!();
    println!("# Client connection info:");
    println!("# Server Public Key (base64): {}", config_file.static_secret_b64);
    println!("# Short ID (hex): {}", hex::encode(short_id));

    Ok(())
}

async fn run_server(config_path: &str) -> anyhow::Result<()> {
    use scf::server::config::ServerConfigFile;

    let config_content = std::fs::read_to_string(config_path)?;
    let config_file: ServerConfigFile = toml::from_str(&config_content)?;
    let config = config_file.to_config().map_err(|e| anyhow::anyhow!(e))?;

    config.validate().map_err(|e| anyhow::anyhow!(e))?;

    tracing::info!("Starting SCF server on {}:{}", config.listen_addr, config.listen_port);
    tracing::info!("Cover server: {}:{}", config.cover_server, config.cover_port);
    tracing::info!("Allowed short IDs: {}", config.allowed_short_ids.len());

    let server = Server::new(config);
    server.run().await?;

    Ok(())
}
