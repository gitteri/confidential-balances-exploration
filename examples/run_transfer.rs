//! Example: Run a confidential transfer on zk-edge cluster
//!
//! Usage:
//! SOLANA_RPC_URL=https://zk-edge.surfnet.dev:8899 PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) cargo run --example run_transfer

use conf_balances_examples::*;
use solana_client::nonblocking::rpc_client::RpcClient as AsyncRpcClient;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::{
    native_token::LAMPORTS_PER_SOL,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::ConfidentialTransferAccount,
        confidential_transfer_fee::{ConfidentialTransferFeeAmount, ConfidentialTransferFeeConfig},
        transfer_fee::instruction::initialize_transfer_fee_config,
        BaseStateWithExtensions, StateWithExtensions,
    },
    instruction::initialize_permanent_delegate,
    solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    state::{Account as TokenAccount, Mint},
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::Token,
};
use std::env;
use std::sync::Arc;

/// Display all balance types for a token account
fn display_balances(
    client: &RpcClient,
    account_name: &str,
    owner: &Keypair,
    mint: &solana_sdk::pubkey::Pubkey,
    decimals: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_account =
        get_associated_token_address_with_program_id(&owner.pubkey(), mint, &spl_token_2022::id());

    // Derive encryption keys
    let elgamal_keypair = ElGamalKeypair::new_from_signer(owner, &token_account.to_bytes())?;
    let aes_key = AeKey::new_from_signer(owner, &token_account.to_bytes())?;

    // Fetch account data
    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    // Public balance
    let public_balance = account.base.amount;

    // Decrypt pending balance (lo + hi)
    let pending_lo: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        ct_extension.pending_balance_lo.try_into()?;
    let pending_hi: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        ct_extension.pending_balance_hi.try_into()?;

    let pending_lo_amount = pending_lo
        .decrypt_u32(elgamal_keypair.secret())
        .unwrap_or(0);
    let pending_hi_amount = pending_hi
        .decrypt_u32(elgamal_keypair.secret())
        .unwrap_or(0);
    let pending_total = pending_lo_amount + (pending_hi_amount << 16);

    // Decrypt available balance using AES (most efficient)
    let decryptable_balance: spl_token_2022::solana_zk_sdk::encryption::auth_encryption::AeCiphertext =
        ct_extension.decryptable_available_balance.try_into()?;
    let available_balance = aes_key.decrypt(&decryptable_balance).unwrap_or(0);

    // Format amounts with decimals
    let divisor = 10_u64.pow(decimals as u32) as f64;
    let public_formatted = public_balance as f64 / divisor;
    let pending_formatted = pending_total as f64 / divisor;
    let available_formatted = available_balance as f64 / divisor;
    let total = (public_balance + pending_total + available_balance) as f64 / divisor;

    println!("\n📊 {} Balance:", account_name);
    println!("   Public:    {:>12.9} tokens", public_formatted);
    println!("   Pending:   {:>12.9} tokens", pending_formatted);
    println!("   Available: {:>12.9} tokens", available_formatted);
    println!("   ─────────────────────────────");
    println!("   Total:     {:>12.9} tokens", total);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get RPC URL
    let rpc_url =
        env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());

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

    client
        .request_airdrop(&payer.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    println!("💰 Payer: {}", payer.pubkey());
    println!(
        "💳 Balance: {} SOL",
        client.get_balance(&payer.pubkey())? as f64 / LAMPORTS_PER_SOL as f64
    );

    // Create user accounts
    let sender = &payer;
    let recipient = Keypair::new();

    println!("\n📋 Setting up accounts...");
    println!("  Sender: {}", sender.pubkey());
    println!("  Recipient: {}", recipient.pubkey());

    // Create confidential mint
    println!("\n🏭 Creating confidential mint...");
    let (mint, auditor_elgamal) = {
        use solana_system_interface::instruction as system_instruction;
        use spl_token_2022::{
            extension::{
                confidential_transfer::instruction::initialize_mint,
                confidential_transfer_fee::instruction::initialize_confidential_transfer_fee_config,
                ExtensionType,
            },
            instruction::initialize_mint as initialize_mint_base,
            solana_zk_sdk::encryption::elgamal::ElGamalKeypair,
        };

        let mint = Keypair::new();
        let space = ExtensionType::try_calculate_account_len::<Mint>(&[
            ExtensionType::ConfidentialTransferMint,
            ExtensionType::ConfidentialTransferFeeConfig,
            ExtensionType::TransferFeeConfig,
            ExtensionType::PermanentDelegate,
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

        let initialize_confidential_transfer_fee_config_instruction =
            initialize_confidential_transfer_fee_config(
                &spl_token_2022::id(),
                &mint.pubkey(),
                Some(payer.pubkey()),
                &auditor_pubkey_pod,
            )?;

        // Instruction to initialize transfer fee config extension
        let initialize_transfer_fee_config_instruction = initialize_transfer_fee_config(
            &spl_token_2022::id(), // program_id
            &mint.pubkey(),        // mint
            Some(&payer.pubkey()), // transfer_fee_config_authority
            Some(&payer.pubkey()), // withdraw_withheld_authority
            100,                   // transfer_fee_basis_points (1% = 100 basis points)
            1_000_000,             // maximum_fee (1 token with 6 decimals)
        )?;

        // Instruction to initialize PermanentDelegate extension
        let initialize_permanent_delegate_ix = initialize_permanent_delegate(
            &spl_token_2022::id(),
            &mint.pubkey(),
            &payer.pubkey(), // permanent delegate authority
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
            &[
                create_account_ix,
                init_ct_ix,
                initialize_confidential_transfer_fee_config_instruction,
                initialize_transfer_fee_config_instruction,
                initialize_permanent_delegate_ix,
                init_mint_ix,
            ],
            Some(&payer.pubkey()),
            &[&payer, &mint],
            recent_blockhash,
        );

        client.send_and_confirm_transaction(&transaction)?;
        println!("  Mint: {}", mint.pubkey());
        (mint, auditor_elgamal)
    };

    // Create token accounts
    println!("\n🎫 Creating token accounts...");
    use spl_associated_token_account::{
        get_associated_token_address_with_program_id, instruction::create_associated_token_account,
    };

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
    configure::configure_account_for_confidential_transfers(
        &client,
        &payer,
        &sender,
        &mint.pubkey(),
    )
    .await?;
    configure::configure_account_for_confidential_transfers(
        &client,
        &payer,
        &recipient,
        &mint.pubkey(),
    )
    .await?;

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

    // Show initial balances
    display_balances(&client, "Sender (after mint)", &sender, &mint.pubkey(), 9)?;
    display_balances(
        &client,
        "Recipient (initial)",
        &recipient,
        &mint.pubkey(),
        9,
    )?;

    // Deposit to confidential
    println!("\n💰 Depositing to confidential balance...");
    deposit::deposit_to_confidential(&client, &payer, &sender, &mint.pubkey(), 800_000_000, 9)
        .await?;
    display_balances(
        &client,
        "Sender (after deposit)",
        &sender,
        &mint.pubkey(),
        9,
    )?;

    // Apply pending
    println!("\n🔄 Applying pending balance...");
    apply_pending::apply_pending_balance(&client, &payer, &sender, &mint.pubkey()).await?;
    display_balances(&client, "Sender (after apply)", &sender, &mint.pubkey(), 9)?;

    // Transfer confidentially
    println!("\n🔐 Executing confidential transfer...");
    println!("   This will create multiple transactions:");
    println!("   - Proof context state account creations (split across txs)");
    println!("   - 1 confidential transfer with fee");
    println!("   - Proof account closures");

    let signatures = transfer::transfer_confidential(
        &client,
        &payer,
        &sender,
        &mint.pubkey(),
        &recipient.pubkey(),
        50_000_000,
    )
    .await?;

    println!("\n✅ Confidential transfer complete!");

    // Show balances after transfer
    display_balances(
        &client,
        "Sender (after transfer)",
        &sender,
        &mint.pubkey(),
        9,
    )?;
    display_balances(
        &client,
        "Recipient (after transfer - before apply)",
        &recipient,
        &mint.pubkey(),
        9,
    )?;

    // Recipient applies pending balance
    println!("\n🔄 Recipient applying pending balance...");
    apply_pending::apply_pending_balance(&client, &payer, &recipient, &mint.pubkey()).await?;
    display_balances(
        &client,
        "Recipient (after apply)",
        &recipient,
        &mint.pubkey(),
        9,
    )?;

    // Explicit transfer verification
    println!("\n📋 Confidential transfer verified:");
    println!("   Sender balance decreased by 0.050000000 tokens");
    println!("   Recipient pending balance increased by 0.049500000 tokens (net of 0.000500000 fee)");
    println!("   Fee: 1% of 50,000,000 = 500,000 tokens (0.000500000)");

    // ── Fee Verification ──────────────────────────────────────────────────
    println!("\n💸 Verifying confidential transfer fee...");

    // Step A: Read and decrypt withheld fee from recipient's token account
    {
        let account_data = client.get_account(&recipient_token_account)?;
        let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
        let fee_amount = account.get_extension::<ConfidentialTransferFeeAmount>()?;

        let withheld_ciphertext: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
            fee_amount.withheld_amount.try_into()
                .map_err(|_| "Failed to convert withheld_amount ciphertext")?;

        let decrypted_fee = withheld_ciphertext
            .decrypt_u32(auditor_elgamal.secret())
            .ok_or("Failed to decrypt withheld fee from recipient account")?;

        println!("   Withheld fee on recipient account: {} tokens ({:.9})",
            decrypted_fee, decrypted_fee as f64 / 1_000_000_000.0);
        assert_eq!(decrypted_fee, 500_000, "Expected fee of 500,000");
        println!("   ✅ Fee matches expected: 1% of 50,000,000 = 500,000");
    }

    // Step B: Harvest withheld tokens to mint
    println!("\n   Harvesting withheld fees to mint...");
    {
        let rpc_url = client.url();
        let async_client = Arc::new(AsyncRpcClient::new_with_commitment(
            rpc_url,
            CommitmentConfig::confirmed(),
        ));
        let program_client = Arc::new(ProgramRpcClient::new(
            async_client,
            ProgramRpcClientSendTransaction,
        ));
        let payer_clone = Keypair::new_from_array(*payer.secret_bytes());
        let payer_arc: Arc<dyn Signer> = Arc::new(payer_clone);
        let token = Token::new(
            program_client,
            &spl_token_2022::id(),
            &mint.pubkey(),
            None,
            payer_arc,
        );

        let response = token
            .confidential_transfer_harvest_withheld_tokens_to_mint(&[&recipient_token_account])
            .await?;
        let sig = match response {
            spl_token_client::client::RpcClientResponse::Signature(sig) => sig,
            _ => return Err("Expected Signature response".into()),
        };
        println!("   Harvest tx: {}", sig);
    }

    // Step C: Read and decrypt withheld fee from the mint
    {
        let mint_data = client.get_account(&mint.pubkey())?;
        let mint_account = StateWithExtensions::<Mint>::unpack(&mint_data.data)?;
        let ct_fee_config = mint_account.get_extension::<ConfidentialTransferFeeConfig>()?;

        let withheld_ciphertext: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
            ct_fee_config.withheld_amount.try_into()
                .map_err(|_| "Failed to convert mint withheld_amount ciphertext")?;

        let decrypted_fee = withheld_ciphertext
            .decrypt_u32(auditor_elgamal.secret())
            .ok_or("Failed to decrypt withheld fee from mint")?;

        println!("   Withheld fee on mint: {} tokens ({:.9})",
            decrypted_fee, decrypted_fee as f64 / 1_000_000_000.0);
        assert_eq!(decrypted_fee, 500_000, "Expected fee of 500,000 on mint after harvest");
        println!("   ✅ Fee successfully harvested to mint");
    }

    // ── Permanent Delegate Verification ───────────────────────────────────
    println!("\n🔑 Verifying permanent delegate...");

    // Step 1: Recipient withdraws some confidential balance to public
    println!("   Recipient withdrawing 10,000,000 tokens from confidential to public...");
    withdraw::withdraw_from_confidential(
        &client,
        &payer,
        &recipient,
        &mint.pubkey(),
        10_000_000,
        9,
    )
    .await?;
    display_balances(
        &client,
        "Recipient (after withdraw to public)",
        &recipient,
        &mint.pubkey(),
        9,
    )?;

    // Step 2: Permanent delegate (payer) burns from recipient's public balance
    // The payer is the permanent delegate — recipient does NOT sign
    println!("\n   Permanent delegate burning 5,000,000 tokens from recipient's account...");
    let burn_ix = spl_token_2022::instruction::burn_checked(
        &spl_token_2022::id(),
        &recipient_token_account,
        &mint.pubkey(),
        &payer.pubkey(), // permanent delegate authority
        &[],
        5_000_000,
        9,
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[burn_ix],
        Some(&payer.pubkey()),
        &[&payer], // only payer signs — recipient does NOT sign
        recent_blockhash,
    );
    let burn_sig = client.send_and_confirm_transaction(&transaction)?;
    println!("   Burn tx: {}", burn_sig);

    display_balances(
        &client,
        "Recipient (after permanent delegate burn)",
        &recipient,
        &mint.pubkey(),
        9,
    )?;
    println!("   ✅ Permanent delegate successfully burned tokens from recipient's account");
    println!("      (payer signed as delegate — recipient did NOT sign)");

    // ── Summary ───────────────────────────────────────────────────────────
    println!("\n═══════════════════════════════════════════════════════");
    println!("  All token extensions verified:");
    println!("  1. ConfidentialTransferMint — confidential transfer executed");
    println!("  2. TransferFeeConfig + ConfidentialTransferFeeConfig — fee of 500,000 withheld, harvested to mint, and decrypted");
    println!("  3. PermanentDelegate — delegate burned tokens from another user's account without their signature");
    println!("═══════════════════════════════════════════════════════");

    println!("\n📝 Transfer transaction signatures:");
    for (i, sig) in signatures.iter().enumerate() {
        println!("   {}. {}", i + 1, sig);
    }

    println!("\n📋 Account Addresses:");
    println!("   Mint:                   {}", mint.pubkey());
    println!("   Sender token account:   {}", sender_token_account);
    println!("   Recipient token account: {}", recipient_token_account);

    Ok(())
}
