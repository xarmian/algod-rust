pub mod autopsy;
pub mod bench;
pub mod capture;
pub mod capture_wire;
pub mod catchpoint;
pub mod catchpoint_sync;
pub mod follow;
pub mod loadgen;
pub mod network_common;
pub mod node;
pub mod observe;
pub mod p2p_transport;
pub mod participate;
pub mod relay;
pub mod replay;
pub mod sync;
pub mod validate;

/// Resolve a network name to an (algod_url, algod_token, network_name) tuple.
///
/// Known networks ("mainnet", "testnet") use public Nodely endpoints.
/// "custom" requires an explicit `--algod-url`.
pub fn resolve_network(
    network: &str,
    algod_url: Option<&str>,
    algod_token: &str,
) -> anyhow::Result<(String, String, &'static str)> {
    match network {
        "mainnet" => Ok((
            "https://mainnet-api.4160.nodely.dev".to_string(),
            String::new(),
            "mainnet",
        )),
        "testnet" => Ok((
            "https://testnet-api.4160.nodely.dev".to_string(),
            String::new(),
            "testnet",
        )),
        "custom" => {
            let url = algod_url
                .ok_or_else(|| anyhow::anyhow!("--algod-url is required when --network=custom"))?;
            Ok((url.to_string(), algod_token.to_string(), "custom"))
        }
        other => {
            anyhow::bail!(
                "unknown network '{}': use mainnet, testnet, or custom",
                other
            );
        }
    }
}
