//! Configure a token account for confidential transfers

use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    signature::Signer,
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::instruction::{configure_account, PubkeyValidityProofData},
        ExtensionType,
    },
    instruction::reallocate,
    solana_zk_sdk::encryption::{
        auth_encryption::AeKey,
        elgamal::ElGamalKeypair,
    },
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;

/// Configure a token account for confidential transfers
///
/// Steps:
/// 1. Reallocate account space for ConfidentialTransferAccount extension
/// 2. Derive ElGamal and AES keys from account authority
/// 3. Generate pubkey validity proof
/// 4. Configure account with proof
pub async fn configure_account_for_confidential_transfers(
    client: &RpcClient,
    payer: &dyn Signer,
    authority: &dyn Signer,
    mint: &solana_sdk::pubkey::Pubkey,
) -> SigResult {
    let token_account = get_associated_token_address_with_program_id(
        &authority.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Derive encryption keys deterministically from authority
    let elgamal_keypair = ElGamalKeypair::new_from_signer(
        authority,
        &token_account.to_bytes(),
    )?;
    let aes_key = AeKey::new_from_signer(
        authority,
        &token_account.to_bytes(),
    )?;

    // Maximum pending deposits before apply_pending_balance must be called
    let max_pending_balance_credit_counter = 65536u64;

    // Initial decryptable balance (encrypted with AES)
    let decryptable_balance = aes_key.encrypt(0);

    // Generate proof that we control the ElGamal public key
    let proof_data = PubkeyValidityProofData::new(&elgamal_keypair)
        .map_err(|_| "Failed to generate pubkey validity proof")?;

    // Proof will be in the next instruction (offset 1)
    let proof_location = ProofLocation::InstructionOffset(
        1.try_into().unwrap(),
        &proof_data,
    );

    // Build instructions
    let mut instructions = vec![];

    // 1. Reallocate to add ConfidentialTransferAccount extension
    instructions.push(reallocate(
        &spl_token_2022::id(),
        &token_account,
        &payer.pubkey(),
        &authority.pubkey(),
        &[&authority.pubkey()],
        &[ExtensionType::ConfidentialTransferAccount],
    )?);

    // 2. Configure account (includes proof instruction)
    instructions.extend(configure_account(
        &spl_token_2022::id(),
        &token_account,
        mint,
        &decryptable_balance.into(),
        max_pending_balance_credit_counter,
        &authority.pubkey(),
        &[],
        proof_location,
    )?);

    // Send transaction
    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer.pubkey()),
        &[authority, payer],
        recent_blockhash,
    );

    let signature = client.send_and_confirm_transaction(&transaction)?;
    println!("✅ Account configured for confidential transfers: {}", signature);

    Ok(signature)
}
