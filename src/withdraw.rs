//! Withdraw tokens from confidential balance to public balance

use crate::types::*;
use solana_client::nonblocking::rpc_client::RpcClient as AsyncRpcClient;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::signature::{Keypair, Signer};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            account_info::WithdrawAccountInfo, ConfidentialTransferAccount,
        },
        BaseStateWithExtensions, StateWithExtensions,
    },
    solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    state::Account as TokenAccount,
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction, RpcClientResponse},
    token::{ComputeUnitLimit, Token},
};
use std::sync::Arc;

/// Helper to extract signature from RpcClientResponse
fn extract_signature(
    response: RpcClientResponse,
) -> Result<solana_sdk::signature::Signature, Box<dyn std::error::Error>> {
    match response {
        RpcClientResponse::Signature(sig) => Ok(sig),
        _ => Err("Expected Signature response".into()),
    }
}

/// Withdraw tokens from confidential balance to public balance
///
/// Uses context state accounts for proofs to avoid transaction size limits
/// when the token account has many extensions (e.g., ConfidentialTransferFeeAmount).
pub async fn withdraw_from_confidential(
    client: &RpcClient,
    payer: &Keypair,
    authority: &Keypair,
    mint: &solana_sdk::pubkey::Pubkey,
    amount: u64,
    decimals: u8,
) -> SigResult {
    let token_account = get_associated_token_address_with_program_id(
        &authority.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Derive encryption keys
    let elgamal_keypair =
        ElGamalKeypair::new_from_signer(authority, &token_account.to_bytes())?;
    let aes_key = AeKey::new_from_signer(authority, &token_account.to_bytes())?;

    // Fetch account state
    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    // Create withdraw account info
    let withdraw_info = WithdrawAccountInfo::new(ct_extension);

    // Decrypt available balance to verify sufficiency
    let available_balance: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        withdraw_info
            .available_balance
            .try_into()
            .map_err(|_| "Failed to convert available_balance")?;

    let current_available = available_balance
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("Failed to decrypt available balance")?;

    if current_available < amount {
        return Err(format!(
            "Insufficient confidential balance: have {}, need {}",
            current_available, amount
        )
        .into());
    }

    // Generate withdrawal proofs
    let proof_data = withdraw_info.generate_proof_data(amount, &elgamal_keypair, &aes_key)?;

    // Create async Token client for context state account operations
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
        mint,
        Some(decimals),
        payer_arc,
    )
    .with_compute_unit_limit(ComputeUnitLimit::Static(400_000));

    // Create context state accounts for proofs (split approach)
    let equality_proof_account = Keypair::new();
    let range_proof_account = Keypair::new();

    token
        .confidential_transfer_create_context_state_account(
            &equality_proof_account.pubkey(),
            &authority.pubkey(),
            &proof_data.equality_proof_data,
            true,
            &[&equality_proof_account],
        )
        .await?;

    token
        .confidential_transfer_create_context_state_account(
            &range_proof_account.pubkey(),
            &authority.pubkey(),
            &proof_data.range_proof_data,
            true,
            &[&range_proof_account],
        )
        .await?;

    // Execute withdraw referencing proof context accounts
    let response = token
        .confidential_transfer_withdraw(
            &token_account,
            &authority.pubkey(),
            Some(&equality_proof_account.pubkey()),
            Some(&range_proof_account.pubkey()),
            amount,
            decimals,
            Some(withdraw_info),
            &elgamal_keypair,
            &aes_key,
            &[authority],
        )
        .await?;
    let signature = extract_signature(response)?;

    // Close proof accounts to reclaim rent
    token
        .confidential_transfer_close_context_state_account(
            &equality_proof_account.pubkey(),
            &token_account,
            &authority.pubkey(),
            &[authority],
        )
        .await?;

    token
        .confidential_transfer_close_context_state_account(
            &range_proof_account.pubkey(),
            &token_account,
            &authority.pubkey(),
            &[authority],
        )
        .await?;

    println!(
        "✅ Withdrew {} tokens to public balance: {}",
        amount, signature
    );
    println!("   Remaining confidential: {}", current_available - amount);

    Ok(signature)
}
