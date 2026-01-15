//! Deposit tokens from public balance to pending confidential balance
//! 
//! This example shows how to deposit tokens into the confidential balance.

use solana_sdk::{signer::Signer, transaction::Transaction};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::extension::confidential_transfer::instruction::deposit;

/// Deposit tokens from public balance to pending confidential balance
pub async fn deposit_tokens(
    client: &solana_client::rpc_client::RpcClient,
    depositor: &dyn Signer,
    mint: &solana_sdk::pubkey::Pubkey,
    deposit_amount: u64,
    decimals: u8,
) -> Result<solana_sdk::signature::Signature, Box<dyn std::error::Error>> {
    // Get associated token account
    let token_account = get_associated_token_address_with_program_id(
        &depositor.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Create deposit instruction
    // This moves tokens from public balance to pending confidential balance
    let deposit_instruction = deposit(
        &spl_token_2022::id(),
        &token_account,
        mint,
        deposit_amount,
        decimals,
        &depositor.pubkey(),
        &[&depositor.pubkey()],
    )?;

    // Build and send transaction
    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[deposit_instruction],
        Some(&depositor.pubkey()),
        &[depositor],
        recent_blockhash,
    );

    let signature = client.send_and_confirm_transaction(&transaction)?;
    
    println!("Deposit successful: {}", signature);
    Ok(signature)
}
