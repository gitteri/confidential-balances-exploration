//! Example: Get and display encrypted confidential balances
//!
//! This example shows how to decrypt and display all balance types
//! (public, pending, available) for a confidential token account.
//!
//! Usage (command line args):
//! cargo run --example get_balances -- <MINT_ADDRESS> <OWNER_KEYPAIR_PATH>
//!
//! Usage (environment variables):
//! MINT_ADDRESS=<mint> OWNER_KEYPAIR=$(cat ~/.config/solana/id.json) cargo run --example get_balances
//!
//! Example:
//! cargo run --example get_balances -- TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA ~/.config/solana/id.json
//!
//! Or with environment variables:
//! MINT_ADDRESS=TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA \
//! OWNER_KEYPAIR=$(cat ~/.config/solana/id.json) \
//! cargo run --example get_balances

use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use serde_json;
use spl_token_2022::{
    extension::{
        confidential_transfer::ConfidentialTransferAccount,
        BaseStateWithExtensions, StateWithExtensions,
    },
    solana_zk_sdk::encryption::{
        auth_encryption::AeKey,
        elgamal::ElGamalKeypair,
    },
    state::Account as TokenAccount,
};
use std::env;

#[derive(Debug)]
struct BalanceBreakdown {
    pub public: u64,
    pub pending: u64,
    pub available: u64,
    pub total: u64,
}

/// Get all balance types for a confidential token account
fn get_balances(
    client: &RpcClient,
    owner: &Keypair,
    mint: &Pubkey,
) -> Result<BalanceBreakdown, Box<dyn std::error::Error>> {
    let token_account = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    println!("🔍 Fetching account: {}", token_account);

    // Derive encryption keys from owner
    let elgamal_keypair = ElGamalKeypair::new_from_signer(
        owner,
        &token_account.to_bytes(),
    )?;
    let aes_key = AeKey::new_from_signer(
        owner,
        &token_account.to_bytes(),
    )?;

    println!("🔑 Derived encryption keys from owner signature");

    // Fetch account data
    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;

    println!("\n📦 Account info:");
    println!("   Mint: {}", account.base.mint);
    println!("   Owner: {}", account.base.owner);

    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    println!("\n🔐 Confidential Transfer Extension:");
    println!("   Approved: {}", bool::from(ct_extension.approved));
    println!("   Allow confidential credits: {}", bool::from(ct_extension.allow_confidential_credits));
    println!("   Allow non-confidential credits: {}", bool::from(ct_extension.allow_non_confidential_credits));
    println!("   Pending balance credit counter: {}", u64::from(ct_extension.pending_balance_credit_counter));

    // 1. Public balance (not encrypted)
    let public_balance = account.base.amount;
    println!("\n💵 Public Balance (visible to all): {}", public_balance);

    // 2. Decrypt pending balance (ElGamal encrypted, split into lo/hi)
    let pending_lo: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        ct_extension.pending_balance_lo.try_into()
            .map_err(|_| "Failed to convert pending_balance_lo")?;
    let pending_hi: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        ct_extension.pending_balance_hi.try_into()
            .map_err(|_| "Failed to convert pending_balance_hi")?;

    let pending_lo_amount = pending_lo.decrypt_u32(elgamal_keypair.secret())
        .ok_or("Failed to decrypt pending_balance_lo")?;
    let pending_hi_amount = pending_hi.decrypt_u32(elgamal_keypair.secret())
        .ok_or("Failed to decrypt pending_balance_hi")?;

    // Combine lo and hi parts (pending is split for range proofs)
    let pending_total = pending_lo_amount + (pending_hi_amount << 16);

    println!("\n🔓 Pending Balance (ElGamal decrypted):");
    println!("   Low bits:  {} (decrypted with ElGamal secret key)", pending_lo_amount);
    println!("   High bits: {} (decrypted with ElGamal secret key)", pending_hi_amount);
    println!("   Combined:  {}", pending_total);

    // 3. Decrypt available balance (ElGamal encrypted)
    let available_balance_elgamal: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        ct_extension.available_balance.try_into()
            .map_err(|_| "Failed to convert available_balance")?;

    let available_elgamal = available_balance_elgamal.decrypt_u32(elgamal_keypair.secret())
        .ok_or("Failed to decrypt available_balance with ElGamal")?;

    // 4. Also decrypt using the AES-encrypted decryptable balance (faster for owner)
    let decryptable_balance: spl_token_2022::solana_zk_sdk::encryption::auth_encryption::AeCiphertext =
        ct_extension.decryptable_available_balance.try_into()
            .map_err(|_| "Failed to convert decryptable_available_balance")?;

    let available_aes = aes_key.decrypt(&decryptable_balance)
        .ok_or("Failed to decrypt decryptable_available_balance with AES")?;

    println!("\n🔓 Available Balance:");
    println!("   ElGamal decryption: {} (using ElGamal secret key)", available_elgamal);
    println!("   AES decryption:     {} (using AES key - faster!)", available_aes);
    println!("   Match: {}", available_elgamal == available_aes);

    let total = public_balance + pending_total + available_aes;

    Ok(BalanceBreakdown {
        public: public_balance,
        pending: pending_total,
        available: available_aes,
        total,
    })
}

/// Display balances in a formatted way
fn display_balances(balances: &BalanceBreakdown, decimals: u8) {
    let divisor = 10_u64.pow(decimals as u32) as f64;

    println!("\n╔═══════════════════════════════════════════════════╗");
    println!("║           BALANCE BREAKDOWN                       ║");
    println!("╠═══════════════════════════════════════════════════╣");
    println!("║                                                   ║");
    println!("║  Public Balance:    {:>12.9} tokens       ║", balances.public as f64 / divisor);
    println!("║  Pending Balance:   {:>12.9} tokens       ║", balances.pending as f64 / divisor);
    println!("║  Available Balance: {:>12.9} tokens       ║", balances.available as f64 / divisor);
    println!("║  ─────────────────────────────────────────────  ║");
    println!("║  Total:             {:>12.9} tokens       ║", balances.total as f64 / divisor);
    println!("║                                                   ║");
    println!("╚═══════════════════════════════════════════════════╝");

    println!("\n📝 Balance Types Explained:");
    println!("   • Public:    Visible to everyone on-chain");
    println!("   • Pending:   Encrypted balance from deposits/transfers (needs apply)");
    println!("   • Available: Encrypted balance ready to transfer or withdraw");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Get mint address (from args or env var)
    let mint_str = if args.len() >= 2 {
        args[1].clone()
    } else if let Ok(mint_env) = env::var("MINT_ADDRESS") {
        mint_env
    } else {
        eprintln!("Error: MINT_ADDRESS not provided");
        eprintln!("\nUsage (args):    {} <MINT_ADDRESS> <OWNER_KEYPAIR_PATH>", args[0]);
        eprintln!("Usage (env):     MINT_ADDRESS=<mint> OWNER_KEYPAIR=<json> {}", args[0]);
        eprintln!("\nExample (args):  {} TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA ~/.config/solana/id.json", args[0]);
        eprintln!("Example (env):   MINT_ADDRESS=TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA OWNER_KEYPAIR=$(cat ~/.config/solana/id.json) {}", args[0]);
        std::process::exit(1);
    };

    // Parse mint address
    let mint = mint_str.parse::<Pubkey>()
        .map_err(|_| format!("Invalid mint address: {}", mint_str))?;

    // Load owner keypair (from args, env var as path, or env var as JSON)
    let owner = if args.len() >= 3 {
        // From command line argument (file path)
        let keypair_path = &args[2];
        read_keypair_file(keypair_path)
            .map_err(|e| format!("Failed to read keypair from {}: {}", keypair_path, e))?
    } else if let Ok(keypair_json) = env::var("OWNER_KEYPAIR") {
        // From environment variable (JSON array)
        let bytes: Vec<u8> = serde_json::from_str(&keypair_json)
            .map_err(|e| format!("Failed to parse OWNER_KEYPAIR as JSON: {}", e))?;

        if bytes.len() != 64 {
            return Err(format!("Invalid keypair: expected 64 bytes, got {}", bytes.len()).into());
        }

        // Extract first 32 bytes (secret key)
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&bytes[0..32]);
        Keypair::new_from_array(secret_key)
    } else {
        eprintln!("Error: Owner keypair not provided");
        eprintln!("\nProvide keypair via:");
        eprintln!("  1. Command line arg:  <OWNER_KEYPAIR_PATH>");
        eprintln!("  2. Environment var:   OWNER_KEYPAIR=$(cat ~/.config/solana/id.json)");
        std::process::exit(1);
    };

    // Connect to RPC
    let rpc_url = env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());

    println!("🔗 Connecting to: {}", rpc_url);
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    println!("👤 Owner: {}", owner.pubkey());
    println!("🪙 Mint: {}\n", mint);

    // Get balances
    let balances = get_balances(&client, &owner, &mint)?;

    // Display formatted
    display_balances(&balances, 9); // Assuming 9 decimals

    println!("\n✅ Balance query complete!");

    Ok(())
}
