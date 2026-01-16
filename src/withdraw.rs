//! Withdraw tokens from confidential balance to public balance

use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    signature::Signer,
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            account_info::WithdrawAccountInfo,
            instruction::withdraw,
            ConfidentialTransferAccount,
        },
        BaseStateWithExtensions, StateWithExtensions,
    },
    solana_zk_sdk::encryption::{
        auth_encryption::AeKey,
        elgamal::ElGamalKeypair,
    },
    state::Account as TokenAccount,
};

/// Withdraw tokens from confidential balance to public balance
///
/// Requires generating zero-knowledge proofs:
/// - Equality proof: proves withdrawal amount matches ciphertext
/// - Range proof: proves remaining balance is non-negative
///
/// These proofs can fit inline in the transaction for small amounts.
pub async fn withdraw_from_confidential(
    client: &RpcClient,
    authority: &dyn Signer,
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
    let elgamal_keypair = ElGamalKeypair::new_from_signer(
        authority,
        &token_account.to_bytes(),
    )?;
    let aes_key = AeKey::new_from_signer(
        authority,
        &token_account.to_bytes(),
    )?;

    // Fetch account state
    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    // Create withdraw account info
    let withdraw_info = WithdrawAccountInfo::new(ct_extension);

    // Decrypt available balance to verify sufficiency
    let available_balance: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        withdraw_info.available_balance.try_into()
            .map_err(|_| "Failed to convert available_balance")?;

    let current_available = available_balance.decrypt_u32(elgamal_keypair.secret())
        .ok_or("Failed to decrypt available balance")?;

    if current_available < amount {
        return Err(format!(
            "Insufficient confidential balance: have {}, need {}",
            current_available, amount
        ).into());
    }

    // Generate withdrawal proofs
    let proof_data = withdraw_info.generate_proof_data(
        amount,
        &elgamal_keypair,
        &aes_key,
    )?;

    // Calculate new decryptable available balance after withdrawal
    let new_available = current_available - amount;
    let new_decryptable_balance = aes_key.encrypt(new_available);

    // Build withdraw instruction (returns Vec<Instruction>)
    use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
    let withdraw_instructions = withdraw(
        &spl_token_2022::id(),
        &token_account,
        mint,
        amount,
        decimals,
        &new_decryptable_balance.into(),
        &authority.pubkey(),
        &[&authority.pubkey()],
        ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof_data.equality_proof_data),
        ProofLocation::InstructionOffset(2.try_into().unwrap(), &proof_data.range_proof_data),
    )?;

    // Send transaction
    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &withdraw_instructions,
        Some(&authority.pubkey()),
        &[authority],
        recent_blockhash,
    );

    let signature = client.send_and_confirm_transaction(&transaction)?;
    println!("✅ Withdrew {} tokens to public balance: {}", amount, signature);
    println!("   Remaining confidential: {}", current_available - amount);

    Ok(signature)
}
