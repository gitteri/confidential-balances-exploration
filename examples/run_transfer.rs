//! Example: Run a confidential transfer on zk-edge cluster
//!
//! Usage:
//! SOLANA_RPC_URL=https://zk-edge.surfnet.dev:8899 PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) cargo run --example run_transfer

use conf_balances_examples::*;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::{
    native_token::LAMPORTS_PER_SOL,
    signature::{Keypair, Signer},
};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get RPC URL
    let rpc_url = env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());

    println!("🔗 Connecting to: {}", rpc_url);

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Load payer from environment
    let payer = if let Ok(keypair_json) = env::var("PAYER_KEYPAIR") {
        let bytes: Vec<u8> = serde_json::from_str(&keypair_json)?;
        if bytes.len() != 64 {
            return Err(format!("Invalid keypair: expected 64 bytes, got {}", bytes.len()).into());
        }
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&bytes[0..32]);
        Keypair::new_from_array(secret_key)
    } else {
        return Err("PAYER_KEYPAIR environment variable not set".into());
    };

    println!("💰 Payer: {}", payer.pubkey());
    println!("💳 Balance: {} SOL", client.get_balance(&payer.pubkey())? as f64 / LAMPORTS_PER_SOL as f64);

    // Create mint authority and user accounts
    let mint_authority = Keypair::new();
    let sender = Keypair::new();
    let recipient = Keypair::new();

    println!("\n📋 Setting up accounts...");
    println!("  Sender: {}", sender.pubkey());
    println!("  Recipient: {}", recipient.pubkey());

    // Fund sender and recipient with SOL for transaction fees
    {
        use solana_system_interface::instruction as system_instruction;
        use solana_sdk::transaction::Transaction;

        let transfer_sender_ix = system_instruction::transfer(&payer.pubkey(), &sender.pubkey(), 100_000_000); // 0.1 SOL
        let transfer_recipient_ix = system_instruction::transfer(&payer.pubkey(), &recipient.pubkey(), 100_000_000); // 0.1 SOL

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[transfer_sender_ix, transfer_recipient_ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        client.send_and_confirm_transaction(&transaction)?;
        println!("✅ Funded sender and recipient accounts");
    }

    // Create confidential mint
    println!("\n🏭 Creating confidential mint...");
    let mint = {
        use solana_sdk::transaction::Transaction;
        use solana_system_interface::instruction as system_instruction;
        use spl_token_2022::{
            extension::{confidential_transfer::instruction::initialize_mint, ExtensionType},
            instruction::initialize_mint as initialize_mint_base,
            solana_zk_sdk::encryption::elgamal::ElGamalKeypair,
            state::Mint,
        };

        let mint = Keypair::new();
        let space = ExtensionType::try_calculate_account_len::<Mint>(&[
            ExtensionType::ConfidentialTransferMint
        ])?;
        let rent = client.get_minimum_balance_for_rent_exemption(space)?;

        let auditor_elgamal = ElGamalKeypair::new_rand();
        let auditor_pubkey_pod: spl_token_2022::solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey =
            (*auditor_elgamal.pubkey()).into();

        let create_account_ix = system_instruction::create_account(
            &payer.pubkey(),
            &mint.pubkey(),
            rent,
            space as u64,
            &spl_token_2022::id(),
        );

        let init_ct_ix = initialize_mint(
            &spl_token_2022::id(),
            &mint.pubkey(),
            None,
            true,
            Some(auditor_pubkey_pod),
        )?;

        let init_mint_ix = initialize_mint_base(
            &spl_token_2022::id(),
            &mint.pubkey(),
            &payer.pubkey(),
            None,
            9,
        )?;

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[create_account_ix, init_ct_ix, init_mint_ix],
            Some(&payer.pubkey()),
            &[&payer, &mint],
            recent_blockhash,
        );

        client.send_and_confirm_transaction(&transaction)?;
        println!("  Mint: {}", mint.pubkey());
        mint
    };

    // Create token accounts
    println!("\n🎫 Creating token accounts...");
    use spl_associated_token_account::{get_associated_token_address_with_program_id, instruction::create_associated_token_account};

    let sender_token_account = get_associated_token_address_with_program_id(
        &sender.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );

    let recipient_token_account = get_associated_token_address_with_program_id(
        &recipient.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );

    let create_sender_ata = create_associated_token_account(
        &payer.pubkey(),
        &sender.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );

    let create_recipient_ata = create_associated_token_account(
        &payer.pubkey(),
        &recipient.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );

    use solana_sdk::transaction::Transaction;
    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[create_sender_ata, create_recipient_ata],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    client.send_and_confirm_transaction(&transaction)?;

    println!("  Sender token account: {}", sender_token_account);
    println!("  Recipient token account: {}", recipient_token_account);

    // Configure accounts
    println!("\n⚙️  Configuring accounts for confidential transfers...");
    configure::configure_account_for_confidential_transfers(&client, &payer, &sender, &mint.pubkey()).await?;
    configure::configure_account_for_confidential_transfers(&client, &payer, &recipient, &mint.pubkey()).await?;

    // Mint tokens
    println!("\n🪙 Minting tokens to sender...");
    let mint_to_ix = spl_token_2022::instruction::mint_to(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &sender_token_account,
        &payer.pubkey(),
        &[],
        1_000_000_000,
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[mint_to_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    client.send_and_confirm_transaction(&transaction)?;

    // Deposit to confidential
    println!("\n💰 Depositing to confidential balance...");
    deposit::deposit_to_confidential(&client, &sender, &mint.pubkey(), 800_000_000, 9).await?;

    // Apply pending
    println!("🔄 Applying pending balance...");
    apply_pending::apply_pending_balance(&client, &sender, &mint.pubkey()).await?;

    // Transfer confidentially
    println!("\n🔐 Executing confidential transfer...");
    println!("   This will create 7 transactions:");
    println!("   - 3 proof context state account creations");
    println!("   - 1 confidential transfer");
    println!("   - 3 proof account closures");

    let signatures = transfer::transfer_confidential(
        &client,
        &payer,
        &sender,
        &mint.pubkey(),
        &recipient.pubkey(),
        50_000_000,
    ).await?;

    println!("\n✅ Confidential transfer complete!");
    println!("\n📝 Transaction signatures:");
    for (i, sig) in signatures.iter().enumerate() {
        println!("   {}. {}", i + 1, sig);
    }

    println!("\n🔗 View on explorer:");
    println!("   https://explorer.solana.com/tx/{}?cluster=custom&customUrl=https%3A%2F%2Fzk-edge.surfnet.dev%3A8899", signatures[3]);

    Ok(())
}
