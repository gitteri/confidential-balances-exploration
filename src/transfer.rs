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
        confidential_transfer_fee::ConfidentialTransferFeeConfig,
        transfer_fee::TransferFeeConfig,
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
    token::{ComputeUnitLimit, ProofAccountWithCiphertext, Token},
};
use spl_token_2022::solana_zk_sdk::zk_elgamal_proof_program::proof_data::batched_range_proof::{
    batched_range_proof_u256::BatchedRangeProofU256Data,
    BatchedRangeProofContext,
};
use spl_token_confidential_transfer_proof_generation::transfer_with_fee::TransferWithFeeProofData;
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
/// This implementation uses the fee-aware transfer variant since the mint has
/// TransferFeeConfig + ConfidentialTransferFeeConfig extensions.
///
/// Steps:
/// 1. Fetches recipient's and auditor's ElGamal public keys from their accounts
/// 2. Fetches fee parameters from the mint's TransferFeeConfig and ConfidentialTransferFeeConfig
/// 3. Generates ZK proofs for the transfer with fee (5 proofs total)
/// 4. Creates temporary on-chain accounts to store the proofs
/// 5. Executes the transfer referencing those proof accounts
/// 6. Closes the proof accounts to reclaim rent
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

    // Fetch mint account data (used for auditor key, fee config, and confidential fee config)
    use spl_token_2022::extension::confidential_transfer::ConfidentialTransferMint;
    use spl_token_2022::state::Mint;
    use spl_token_2022::solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey;

    let mint_account_data = client.get_account(mint)?;
    let mint_account = StateWithExtensions::<Mint>::unpack(&mint_account_data.data)?;

    // Get auditor ElGamal pubkey from ConfidentialTransferMint
    let mint_ct_extension = mint_account.get_extension::<ConfidentialTransferMint>()?;
    let auditor_elgamal_pubkey: Option<spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalPubkey> =
        Option::<PodElGamalPubkey>::from(mint_ct_extension.auditor_elgamal_pubkey)
            .map(|pk| pk.try_into())
            .transpose()
            .map_err(|_| "Failed to convert auditor ElGamal pubkey")?;

    // Get fee parameters from TransferFeeConfig
    let transfer_fee_config = mint_account.get_extension::<TransferFeeConfig>()?;
    let epoch_info = client.get_epoch_info()?;
    let epoch_fee = transfer_fee_config.get_epoch_fee(epoch_info.epoch);
    let fee_rate_basis_points: u16 = epoch_fee.transfer_fee_basis_points.into();
    let maximum_fee: u64 = epoch_fee.maximum_fee.into();

    // Get withdraw withheld authority ElGamal pubkey from ConfidentialTransferFeeConfig
    let ct_fee_config = mint_account.get_extension::<ConfidentialTransferFeeConfig>()?;
    let withdraw_withheld_authority_elgamal_pubkey: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalPubkey =
        ct_fee_config.withdraw_withheld_authority_elgamal_pubkey.try_into()
            .map_err(|_| "Failed to convert withdraw withheld authority ElGamal pubkey")?;

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

    println!("🔐 Generating transfer with fee proofs for {} tokens (fee: {} bps, max: {})...",
        amount, fee_rate_basis_points, maximum_fee);

    // Generate transfer with fee proofs (5 proofs instead of 3)
    let TransferWithFeeProofData {
        equality_proof_data,
        transfer_amount_ciphertext_validity_proof_data_with_ciphertext,
        percentage_with_cap_proof_data,
        fee_ciphertext_validity_proof_data,
        range_proof_data,
    } = transfer_info.generate_split_transfer_with_fee_proof_data(
        amount,
        &sender_elgamal,
        &sender_aes,
        &recipient_elgamal_pubkey,
        auditor_elgamal_pubkey.as_ref(),
        &withdraw_withheld_authority_elgamal_pubkey,
        fee_rate_basis_points,
        maximum_fee,
    )?;

    println!("📦 Creating proof context state accounts...");

    // Create async RpcClient for spl-token-client
    let rpc_url = client.url();
    let async_client = Arc::new(AsyncRpcClient::new_with_commitment(
        rpc_url,
        CommitmentConfig::confirmed(),
    ));

    // Create Token client wrapper
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
    )
    .with_compute_unit_limit(ComputeUnitLimit::Static(1_400_000));

    // Create proof context state accounts (5 for transfer with fee)
    // All proofs use split=true (separate create + verify txs) because the
    // combined create+verify transactions exceed the 1232-byte tx size limit.
    // The range proof (U256) is too large even for split, so it uses the
    // record account approach (chunked writes + verify from record).
    let equality_proof_account = Keypair::new();
    let ciphertext_validity_proof_account = Keypair::new();
    let percentage_with_cap_proof_account = Keypair::new();
    let fee_ciphertext_validity_proof_account = Keypair::new();
    let range_proof_account = Keypair::new();

    let mut signatures = Vec::new();

    // Create equality proof account (split: create account, then verify proof)
    let response = token.confidential_transfer_create_context_state_account(
        &equality_proof_account.pubkey(),
        &sender.pubkey(),
        &equality_proof_data,
        true,
        &[&equality_proof_account],
    ).await?;
    signatures.push(extract_signature(response)?);

    // Create ciphertext validity proof account (split)
    let response = token.confidential_transfer_create_context_state_account(
        &ciphertext_validity_proof_account.pubkey(),
        &sender.pubkey(),
        &transfer_amount_ciphertext_validity_proof_data_with_ciphertext.proof_data,
        true,
        &[&ciphertext_validity_proof_account],
    ).await?;
    signatures.push(extract_signature(response)?);

    // Create percentage with cap proof account (split)
    let response = token.confidential_transfer_create_context_state_account(
        &percentage_with_cap_proof_account.pubkey(),
        &sender.pubkey(),
        &percentage_with_cap_proof_data,
        true,
        &[&percentage_with_cap_proof_account],
    ).await?;
    signatures.push(extract_signature(response)?);

    // Create fee ciphertext validity proof account (split)
    let response = token.confidential_transfer_create_context_state_account(
        &fee_ciphertext_validity_proof_account.pubkey(),
        &sender.pubkey(),
        &fee_ciphertext_validity_proof_data,
        true,
        &[&fee_ciphertext_validity_proof_account],
    ).await?;
    signatures.push(extract_signature(response)?);

    // Range proof (U256) is too large even for split — use record account approach:
    // 1. Write proof data to a record account (chunked across multiple txs)
    // 2. Verify proof from the record account into a context state account
    // 3. Close the record account
    let range_proof_record_account = Keypair::new();

    let record_responses = token.confidential_transfer_create_record_account(
        &range_proof_record_account.pubkey(),
        &sender.pubkey(),
        &range_proof_data,
        &range_proof_record_account,
        sender,
    ).await?;
    for response in record_responses {
        signatures.push(extract_signature(response)?);
    }

    // Create context state account from the record account
    let response = token.confidential_transfer_create_context_state_account_from_record::<_, BatchedRangeProofU256Data, BatchedRangeProofContext>(
        &range_proof_account.pubkey(),
        &sender.pubkey(),
        &range_proof_record_account.pubkey(),
        &[&range_proof_account],
    ).await?;
    signatures.push(extract_signature(response)?);

    // Close the record account to reclaim rent
    token.confidential_transfer_close_record_account(
        &range_proof_record_account.pubkey(),
        &sender_token_account,
        &sender.pubkey(),
        &[sender],
    ).await?;

    println!("🔄 Executing confidential transfer with fee...");

    // Execute transfer using proof context accounts
    let ciphertext_validity_proof = ProofAccountWithCiphertext {
        context_state_account: ciphertext_validity_proof_account.pubkey(),
        ciphertext_lo: transfer_amount_ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
        ciphertext_hi: transfer_amount_ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
    };

    let response = token.confidential_transfer_transfer_with_fee(
        &sender_token_account,
        &recipient_token_account,
        &sender.pubkey(),
        Some(&equality_proof_account.pubkey()),
        Some(&ciphertext_validity_proof),
        Some(&percentage_with_cap_proof_account.pubkey()),
        Some(&fee_ciphertext_validity_proof_account.pubkey()),
        Some(&range_proof_account.pubkey()),
        amount,
        None, // Let Token client fetch account info internally
        &sender_elgamal,
        &sender_aes,
        &recipient_elgamal_pubkey,
        auditor_elgamal_pubkey.as_ref(),
        &withdraw_withheld_authority_elgamal_pubkey,
        fee_rate_basis_points,
        maximum_fee,
        &[sender],
    ).await?;
    signatures.push(extract_signature(response)?);

    println!("🧹 Closing proof context accounts...");

    // Close proof accounts to reclaim rent (5 accounts)
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
        &percentage_with_cap_proof_account.pubkey(),
        &sender_token_account,
        &sender.pubkey(),
        &[sender],
    ).await?;
    signatures.push(extract_signature(response)?);

    let response = token.confidential_transfer_close_context_state_account(
        &fee_ciphertext_validity_proof_account.pubkey(),
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
