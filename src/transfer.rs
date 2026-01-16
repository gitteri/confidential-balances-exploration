//! Confidential transfer between accounts
//!
//! This implements confidential transfers using proof context state accounts
//! to avoid transaction size limitations.

use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_client::nonblocking::rpc_client::RpcClient as AsyncRpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::{
    signature::{Keypair, Signer},
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            account_info::TransferAccountInfo,
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
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction, RpcClientResponse},
    token::{ProofAccountWithCiphertext, Token},
};
use spl_token_confidential_transfer_proof_generation::transfer::TransferProofData;
use std::sync::Arc;

/// Helper to extract signature from RpcClientResponse
fn extract_signature(response: RpcClientResponse) -> Result<solana_sdk::signature::Signature, Box<dyn std::error::Error>> {
    match response {
        RpcClientResponse::Signature(sig) => Ok(sig),
        _ => Err("Expected Signature response".into()),
    }
}

/// Transfer tokens confidentially from sender to recipient using proof context state accounts
///
/// This implementation:
/// 1. Fetches recipient's and auditor's ElGamal public keys from their accounts
/// 2. Generates ZK proofs for the transfer
/// 3. Creates temporary on-chain accounts to store the proofs
/// 4. Executes the transfer referencing those proof accounts
/// 5. Closes the proof accounts to reclaim rent
///
/// This approach avoids transaction size limitations by not including proofs inline.
///
/// Note: sender must be a Keypair (not just a Signer) because the Token client requires
/// cloning the keypair for fee payment.
///
/// Returns signatures for all transactions (proof creation + transfer + cleanup)
pub async fn transfer_confidential(
    client: &RpcClient,
    _payer: &dyn Signer,
    sender: &Keypair,
    mint: &solana_sdk::pubkey::Pubkey,
    recipient: &solana_sdk::pubkey::Pubkey,
    amount: u64,
) -> MultiSigResult {
    let sender_token_account = get_associated_token_address_with_program_id(
        &sender.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    let recipient_token_account = get_associated_token_address_with_program_id(
        recipient,
        mint,
        &spl_token_2022::id(),
    );

    // Fetch recipient's ElGamal public key from their account
    let recipient_account_data = client.get_account(&recipient_token_account)?;
    let recipient_account = StateWithExtensions::<TokenAccount>::unpack(&recipient_account_data.data)?;
    let recipient_ct_extension = recipient_account.get_extension::<ConfidentialTransferAccount>()?;
    let recipient_elgamal_pubkey: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalPubkey =
        recipient_ct_extension.elgamal_pubkey.try_into()
            .map_err(|_| "Failed to convert recipient ElGamal pubkey")?;

    // Fetch auditor's ElGamal public key from the mint account
    use spl_token_2022::extension::confidential_transfer::ConfidentialTransferMint;
    use spl_token_2022::state::Mint;
    use spl_token_2022::solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey;

    let mint_account_data = client.get_account(mint)?;
    let mint_account = StateWithExtensions::<Mint>::unpack(&mint_account_data.data)?;
    let mint_ct_extension = mint_account.get_extension::<ConfidentialTransferMint>()?;
    let auditor_elgamal_pubkey: Option<spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalPubkey> =
        Option::<PodElGamalPubkey>::from(mint_ct_extension.auditor_elgamal_pubkey)
            .map(|pk| pk.try_into())
            .transpose()
            .map_err(|_| "Failed to convert auditor ElGamal pubkey")?;

    // Derive sender's encryption keys
    let sender_elgamal = ElGamalKeypair::new_from_signer(
        sender,
        &sender_token_account.to_bytes(),
    )?;

    let sender_aes = AeKey::new_from_signer(
        sender,
        &sender_token_account.to_bytes(),
    )?;

    // Fetch sender's account state
    let account_data = client.get_account(&sender_token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    // Create transfer account info
    let transfer_info = TransferAccountInfo::new(ct_extension);

    // Verify sufficient balance
    let available_balance: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        transfer_info.available_balance.try_into()
            .map_err(|_| "Failed to convert available_balance")?;

    let current_available = available_balance.decrypt_u32(sender_elgamal.secret())
        .ok_or("Failed to decrypt available balance")?;

    if current_available < amount {
        return Err(format!(
            "Insufficient balance: have {}, need {}",
            current_available, amount
        ).into());
    }

    println!("🔐 Generating transfer proofs for {} tokens...", amount);

    // Generate transfer proofs
    let TransferProofData {
        equality_proof_data,
        ciphertext_validity_proof_data_with_ciphertext,
        range_proof_data,
    } = transfer_info.generate_split_transfer_proof_data(
        amount,
        &sender_elgamal,
        &sender_aes,
        &recipient_elgamal_pubkey,
        auditor_elgamal_pubkey.as_ref(),
    )?;

    println!("📦 Creating proof context state accounts...");

    // Create async RpcClient for spl-token-client
    let rpc_url = client.url();
    let async_client = Arc::new(AsyncRpcClient::new_with_commitment(
        rpc_url,
        CommitmentConfig::confirmed(),
    ));

    // Create Token client wrapper
    // Note: We use sender as the fee payer for Token operations since they must
    // have SOL anyway to pay for the proof account rent
    let program_client = Arc::new(ProgramRpcClient::new(
        async_client,
        ProgramRpcClientSendTransaction,
    ));

    // Clone sender keypair to create Arc<dyn Signer> for Token client
    let sender_clone = Keypair::new_from_array(*sender.secret_bytes());
    let sender_arc: Arc<dyn Signer> = Arc::new(sender_clone);

    let token = Token::new(
        program_client,
        &spl_token_2022::id(),
        mint,
        None, // decimals - not needed for this operation
        sender_arc,
    );

    // Create proof context state accounts
    let equality_proof_account = Keypair::new();
    let ciphertext_validity_proof_account = Keypair::new();
    let range_proof_account = Keypair::new();

    let mut signatures = Vec::new();

    // Create equality proof account
    let response = token.confidential_transfer_create_context_state_account(
        &equality_proof_account.pubkey(),
        &sender.pubkey(),
        &equality_proof_data,
        false,
        &[&equality_proof_account],
    ).await?;
    signatures.push(extract_signature(response)?);

    // Create ciphertext validity proof account
    let response = token.confidential_transfer_create_context_state_account(
        &ciphertext_validity_proof_account.pubkey(),
        &sender.pubkey(),
        &ciphertext_validity_proof_data_with_ciphertext.proof_data,
        false,
        &[&ciphertext_validity_proof_account],
    ).await?;
    signatures.push(extract_signature(response)?);

    // Create range proof account
    let response = token.confidential_transfer_create_context_state_account(
        &range_proof_account.pubkey(),
        &sender.pubkey(),
        &range_proof_data,
        true, // range proofs require split proof
        &[&range_proof_account],
    ).await?;
    signatures.push(extract_signature(response)?);

    println!("🔄 Executing confidential transfer...");

    // Execute transfer using proof context accounts
    let ciphertext_validity_proof = ProofAccountWithCiphertext {
        context_state_account: ciphertext_validity_proof_account.pubkey(),
        ciphertext_lo: ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
        ciphertext_hi: ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
    };

    let response = token.confidential_transfer_transfer(
        &sender_token_account,
        &recipient_token_account,
        &sender.pubkey(),
        Some(&equality_proof_account.pubkey()),
        Some(&ciphertext_validity_proof),
        Some(&range_proof_account.pubkey()),
        amount,
        None, // Let Token client fetch account info internally
        &sender_elgamal,
        &sender_aes,
        &recipient_elgamal_pubkey,
        auditor_elgamal_pubkey.as_ref(),
        &[sender],
    ).await?;
    signatures.push(extract_signature(response)?);

    println!("🧹 Closing proof context accounts...");

    // Close proof accounts to reclaim rent
    let response = token.confidential_transfer_close_context_state_account(
        &equality_proof_account.pubkey(),
        &sender_token_account,
        &sender.pubkey(),
        &[sender],
    ).await?;
    signatures.push(extract_signature(response)?);

    let response = token.confidential_transfer_close_context_state_account(
        &ciphertext_validity_proof_account.pubkey(),
        &sender_token_account,
        &sender.pubkey(),
        &[sender],
    ).await?;
    signatures.push(extract_signature(response)?);

    let response = token.confidential_transfer_close_context_state_account(
        &range_proof_account.pubkey(),
        &sender_token_account,
        &sender.pubkey(),
        &[sender],
    ).await?;
    signatures.push(extract_signature(response)?);

    println!("✅ Transfer complete with {} transactions", signatures.len());

    Ok(signatures)
}
