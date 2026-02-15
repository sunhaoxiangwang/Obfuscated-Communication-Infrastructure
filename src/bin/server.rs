//! SCF Server Binary
//!
//! Usage: scf-server [OPTIONS]
//!
//! Options:
//!   -c, --config <FILE>  Path to configuration file
//!   -g, --generate       Generate new server configuration
//!   -h, --help           Print help information

use std::env;

use scf::server::{Server, ServerConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing — respects RUST_LOG env var (e.g. RUST_LOG=debug)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
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
        "--show-pubkey" => {
            if args.len() < 3 {
                eprintln!("Error: --show-pubkey requires a config file path");
                return Ok(());
            }
            show_pubkey(&args[2])?;
        }
        "--add-client" => {
            if args.len() < 3 {
                eprintln!("Error: --add-client requires a config file path");
                return Ok(());
            }
            add_client(&args[2])?;
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
    -c, --config <FILE>     Path to configuration file
    -g, --generate          Generate new server configuration
    --show-pubkey <FILE>    Show server public key from existing config
    --add-client <FILE>     Generate a new client short ID and update config
    -h, --help              Print help information

EXAMPLES:
    Generate a new configuration:
        scf-server --generate > server.toml

    Run the server:
        scf-server --config server.toml

    Show public key for clients:
        scf-server --show-pubkey server.toml

    Add a new client:
        scf-server --add-client server.toml
"#
    );
}

fn generate_config() -> anyhow::Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use scf::server::config::ServerConfigFile;

    let mut config = ServerConfig::new_random("0.0.0.0", 443, "www.microsoft.com");
    let short_id = config.generate_short_id();
    let public_key = config.public_key();

    let config_file = ServerConfigFile::from_config(&config);

    println!("# SCF Server Configuration");
    println!("# Generated: {}", chrono::Utc::now());
    println!();
    println!("{}", toml::to_string_pretty(&config_file)?);
    println!();
    println!("# Client connection info (put these in client.json):");
    println!("# Server Public Key (base64): {}", STANDARD.encode(public_key.as_bytes()));
    println!("# Short ID (hex): {}", hex::encode(short_id));

    Ok(())
}

fn show_pubkey(config_path: &str) -> anyhow::Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use scf::server::config::ServerConfigFile;

    let content = std::fs::read_to_string(config_path)?;
    let config_file: ServerConfigFile = toml::from_str(&content)?;
    let config = config_file.to_config().map_err(|e: String| anyhow::anyhow!(e))?;
    let public_key = config.public_key();

    println!("Server Public Key (base64): {}", STANDARD.encode(public_key.as_bytes()));
    println!();
    println!("Allowed Short IDs (hex):");
    for (i, id) in config.allowed_short_ids.iter().enumerate() {
        println!("  [{}] {}", i + 1, hex::encode(id));
    }

    Ok(())
}

fn add_client(config_path: &str) -> anyhow::Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use scf::server::config::ServerConfigFile;

    let content = std::fs::read_to_string(config_path)?;
    let mut config_file: ServerConfigFile = toml::from_str(&content)?;

    // Generate new short ID
    let short_id: [u8; 8] = scf::crypto::SecureRandom::bytes();
    let short_id_hex = hex::encode(short_id);
    config_file.allowed_short_ids.push(short_id_hex.clone());

    // Write updated config back
    let mut output = String::new();
    output.push_str("# SCF Server Configuration\n\n");
    output.push_str(&toml::to_string_pretty(&config_file)?);
    std::fs::write(config_path, &output)?;

    // Derive public key for the client config
    let config = config_file.to_config().map_err(|e: String| anyhow::anyhow!(e))?;
    let public_key = config.public_key();

    println!("New client added successfully!");
    println!();
    println!("Give your friend this client.json:");
    println!();
    println!("{{");
    println!("    \"server_public_key\": \"{}\",", STANDARD.encode(public_key.as_bytes()));
    println!("    \"short_id\": \"{}\",", short_id_hex);
    println!("    \"cover_sni\": \"{}\",", config.cover_server);
    println!("    \"server_addr\": \"YOUR_SERVER_IP\",");
    println!("    \"server_port\": {}", config.listen_port);
    println!("}}");

    Ok(())
}

async fn run_server(config_path: &str) -> anyhow::Result<()> {
    use scf::server::config::ServerConfigFile;

    let config_content = std::fs::read_to_string(config_path)?;
    let config_file: ServerConfigFile = toml::from_str(&config_content)?;
    let config = config_file.to_config().map_err(|e: String| anyhow::anyhow!(e))?;

    config.validate().map_err(|e: String| anyhow::anyhow!(e))?;

    tracing::info!("Starting SCF server on {}:{}", config.listen_addr, config.listen_port);
    tracing::info!("Cover server: {}:{}", config.cover_server, config.cover_port);
    tracing::info!("Allowed short IDs: {}", config.allowed_short_ids.len());

    let server = Server::new(config);
    server.run().await?;

    Ok(())
}
