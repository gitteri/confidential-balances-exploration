//! Apply pending balance to available confidential balance
//! 
//! After depositing or receiving a transfer, tokens are in "pending" state.
//! This instruction moves them to "available" so they can be spent.

use solana_sdk::{signer::Signer, transaction::Transaction};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    error::TokenError,
    extension::{
        confidential_transfer::{
            account_info::ApplyPendingBalanceAccountInfo,
            instruction::apply_pending_balance,
            ConfidentialTransferAccount,
        },
        BaseStateWithExtensions,
    },
    solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
};

/// Apply pending balance to available balance
pub async fn apply_pending(
    client: &solana_client::rpc_client::RpcClient,
    authority: &dyn Signer,
    mint: &solana_sdk::pubkey::Pubkey,
) -> Result<solana_sdk::signature::Signature, Box<dyn std::error::Error>> {
    // Get token account
    let token_account = get_associated_token_address_with_program_id(
        &authority.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Derive encryption keys
    let elgamal_keypair = ElGamalKeypair::new_from_signer(authority, &token_account.to_bytes())?;
    let aes_key = AeKey::new_from_signer(authority, &token_account.to_bytes())?;

    // Get account data
    let account_data = client.get_account(&token_account)?.data;
    let account = spl_token_2022::extension::StateWithExtensionsOwned::<
        spl_token_2022::state::Account,
    >::unpack(account_data)?;

    // Get confidential transfer extension
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;
    let apply_info = ApplyPendingBalanceAccountInfo::new(ct_extension);

    // Get expected pending balance credit counter
    let expected_counter = apply_info.pending_balance_credit_counter();

    // Calculate new decryptable available balance
    let new_decryptable_balance = apply_info
        .new_decryptable_available_balance(elgamal_keypair.secret(), &aes_key)
        .map_err(|_| TokenError::AccountDecryption)?;

    // Create apply instruction
    let apply_instruction = apply_pending_balance(
        &spl_token_2022::id(),
        &token_account,
        expected_counter,
        &new_decryptable_balance.into(),
        &authority.pubkey(),
        &[&authority.pubkey()],
    )?;

    // Build and send transaction
    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[apply_instruction],
        Some(&authority.pubkey()),
        &[authority],
        recent_blockhash,
    );

    let signature = client.send_and_confirm_transaction(&transaction)?;

    println!("Apply pending balance successful: {}", signature);
    Ok(signature)
}
