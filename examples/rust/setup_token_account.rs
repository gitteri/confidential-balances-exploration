//! Configure a token account for confidential transfers
//! 
//! Before using confidential transfers, each token account must:
//! 1. Reallocate space for the ConfidentialTransferAccount extension
//! 2. Configure with ElGamal public key and PubkeyValidityProof

use solana_sdk::{signer::Signer, transaction::Transaction};
use spl_associated_token_account::{
    get_associated_token_address_with_program_id, instruction::create_associated_token_account,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::instruction::{configure_account, PubkeyValidityProofData},
        ExtensionType,
    },
    instruction::reallocate,
    solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
};
use spl_token_confidential_transfer_proof_extraction::instruction::{ProofData, ProofLocation};

/// Set up a token account for confidential transfers
pub async fn setup_token_account(
    client: &solana_client::rpc_client::RpcClient,
    fee_payer: &dyn Signer,
    token_account_authority: &dyn Signer,
    mint: &solana_sdk::pubkey::Pubkey,
) -> Result<solana_sdk::signature::Signature, Box<dyn std::error::Error>> {
    // Get associated token address
    let token_account = get_associated_token_address_with_program_id(
        &token_account_authority.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Create ATA instruction
    let create_ata_ix = create_associated_token_account(
        &fee_payer.pubkey(),
        &token_account_authority.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Reallocate for confidential transfer extension
    let reallocate_ix = reallocate(
        &spl_token_2022::id(),
        &token_account,
        &fee_payer.pubkey(),
        &token_account_authority.pubkey(),
        &[&token_account_authority.pubkey()],
        &[ExtensionType::ConfidentialTransferAccount],
    )?;

    // Derive encryption keys from authority signature
    let elgamal_keypair =
        ElGamalKeypair::new_from_signer(token_account_authority, &token_account.to_bytes())?;
    let aes_key =
        AeKey::new_from_signer(token_account_authority, &token_account.to_bytes())?;

    // Maximum pending deposits before ApplyPendingBalance must be called
    let maximum_pending_balance_credit_counter = 65536u64;

    // Initial balance is 0
    let decryptable_balance = aes_key.encrypt(0);

    // Generate pubkey validity proof (proves we know the secret key)
    let proof_data = PubkeyValidityProofData::new(&elgamal_keypair)
        .map_err(|_| spl_token_2022::error::TokenError::ProofGeneration)?;

    // Include proof in same transaction (offset 1 = next instruction)
    let proof_location = ProofLocation::InstructionOffset(
        1.try_into().unwrap(),
        ProofData::InstructionData(&proof_data),
    );

    // Configure account instruction (includes proof instruction)
    let configure_ix = configure_account(
        &spl_token_2022::id(),
        &token_account,
        mint,
        &decryptable_balance.into(),
        maximum_pending_balance_credit_counter,
        &token_account_authority.pubkey(),
        &[],
        proof_location,
    )?;

    // Build transaction
    let mut instructions = vec![create_ata_ix, reallocate_ix];
    instructions.extend(configure_ix);

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&fee_payer.pubkey()),
        &[token_account_authority, fee_payer],
        recent_blockhash,
    );

    let signature = client.send_and_confirm_transaction(&transaction)?;

    println!("Token account configured for confidential transfers: {}", signature);
    Ok(signature)
}
