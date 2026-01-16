//! Apply pending balance to available balance

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
            instruction::apply_pending_balance as apply_pending_balance_instruction,
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

/// Apply pending balance to available balance
///
/// This moves tokens from the "pending" state (where they land after deposits)
/// to the "available" state where they can be spent in transfers.
///
/// Requires:
/// - Decrypting current pending and available balances
/// - Computing new available balance
/// - Encrypting new balance with AES for efficient owner viewing
pub async fn apply_pending_balance(
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

    // Decrypt current balances
    let pending_balance_lo: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        ct_extension.pending_balance_lo.try_into()
            .map_err(|_| "Failed to convert pending_balance_lo")?;
    let pending_balance_hi: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        ct_extension.pending_balance_hi.try_into()
            .map_err(|_| "Failed to convert pending_balance_hi")?;
    let available_balance: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        ct_extension.available_balance.try_into()
            .map_err(|_| "Failed to convert available_balance")?;

    let pending_lo = pending_balance_lo.decrypt_u32(elgamal_keypair.secret())
        .ok_or("Failed to decrypt pending_balance_lo")?;
    let pending_hi = pending_balance_hi.decrypt_u32(elgamal_keypair.secret())
        .ok_or("Failed to decrypt pending_balance_hi")?;
    let current_available = available_balance.decrypt_u32(elgamal_keypair.secret())
        .ok_or("Failed to decrypt available_balance")?;

    // Calculate new available balance
    let pending_total = pending_lo + (pending_hi << 16);
    let new_available = current_available + pending_total;

    // Encrypt new available balance with AES for owner
    let new_decryptable_balance = aes_key.encrypt(new_available);

    // Get expected pending balance credit counter
    let expected_counter: u64 = ct_extension.pending_balance_credit_counter.into();

    // Create apply pending balance instruction
    let apply_ix = apply_pending_balance_instruction(
        &spl_token_2022::id(),
        &token_account,
        expected_counter,
        &new_decryptable_balance.into(),
        &authority.pubkey(),
        &[&authority.pubkey()],
    )?;

    // Send transaction
    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[apply_ix],
        Some(&payer.pubkey()),
        &[payer, authority],
        recent_blockhash,
    );

    let signature = client.send_and_confirm_transaction(&transaction)?;
    println!("✅ Applied pending balance. New available: {} tokens. Tx: {}", new_available, signature);

    Ok(signature)
}
