//! Withdraw tokens from confidential balance to public balance
//!
//! This example shows how to withdraw tokens from the confidential (encrypted)
//! balance back to the public (visible) balance.
//!
//! ## Why Withdraw?
//!
//! - Convert confidential tokens to standard SPL tokens
//! - Enable trading on DEXes that don't support confidential transfers
//! - Exit the confidential system entirely
//!
//! ## Proof Required
//!
//! Withdrawals require a **range proof** to prove:
//! 1. The withdrawal amount is valid (not negative)
//! 2. The remaining balance after withdrawal is non-negative

use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    signature::Signature,
    signer::{keypair::Keypair, Signer},
    transaction::Transaction,
};
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::ElGamalKeypair,
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
    state::Account as TokenAccount,
};
use spl_token_confidential_transfer_proof_generation::withdraw::WithdrawProofData;

/// Withdraw tokens from confidential balance to public balance
///
/// # Arguments
/// * `client` - RPC client
/// * `owner` - Account owner (signer)
/// * `elgamal_keypair` - Owner's ElGamal keypair
/// * `ae_key` - Owner's AES key for decryptable balance
/// * `mint` - Token mint address
/// * `withdraw_amount` - Amount to withdraw to public balance
/// * `decimals` - Token decimals
pub async fn withdraw_confidential(
    client: &RpcClient,
    owner: &dyn Signer,
    elgamal_keypair: &ElGamalKeypair,
    ae_key: &AeKey,
    mint: &Pubkey,
    withdraw_amount: u64,
    decimals: u8,
) -> Result<Signature, Box<dyn std::error::Error>> {
    // Step 1: Get the token account
    let token_account = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Step 2: Fetch current confidential state
    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    // Step 3: Create withdraw info and verify balance
    let withdraw_info = WithdrawAccountInfo::new(ct_extension);
    
    // Decrypt the available balance
    let current_available = withdraw_info
        .available_balance
        .decrypt(elgamal_keypair.secret())
        .ok_or("Failed to decrypt available balance")?;
    
    if current_available < withdraw_amount {
        return Err(format!(
            "Insufficient confidential balance: have {}, need {}",
            current_available, withdraw_amount
        ).into());
    }

    // Step 4: Generate withdrawal proof
    //
    // The proof demonstrates:
    // - The withdrawal amount is what we claim (equality proof)
    // - The remaining balance is non-negative (range proof)
    let withdraw_proof_data = WithdrawProofData::new(
        &withdraw_info,
        elgamal_keypair,
        ae_key,
        withdraw_amount,
    )?;

    // Step 5: Build the withdraw instruction
    //
    // For withdrawals, the proof can often fit inline in the transaction
    // (unlike transfers which need context accounts)
    let withdraw_instruction = withdraw(
        &spl_token_2022::id(),
        &token_account,
        mint,
        withdraw_amount,
        decimals,
        withdraw_proof_data.new_decryptable_available_balance.into(),
        &owner.pubkey(),
        &[&owner.pubkey()],
        // Proof location - either inline or in context account
        &withdraw_proof_data.equality_proof,
        &withdraw_proof_data.range_proof,
    )?;

    // Step 6: Send transaction
    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[withdraw_instruction],
        Some(&owner.pubkey()),
        &[owner],
        recent_blockhash,
    );

    let signature = client.send_and_confirm_transaction(&transaction)?;
    
    println!("Withdrawal successful!");
    println!("  Amount: {} tokens", withdraw_amount);
    println!("  Transaction: {}", signature);
    println!("  Remaining confidential balance: {}", current_available - withdraw_amount);

    Ok(signature)
}

/// Withdraw with split proofs (for larger amounts that don't fit inline)
///
/// When withdrawal amounts are large or when combined with other operations,
/// the proofs may need to be stored in context accounts first.
pub async fn withdraw_with_split_proofs(
    client: &RpcClient,
    owner: &dyn Signer,
    elgamal_keypair: &ElGamalKeypair,
    ae_key: &AeKey,
    mint: &Pubkey,
    withdraw_amount: u64,
    decimals: u8,
) -> Result<Vec<Signature>, Box<dyn std::error::Error>> {
    let token_account = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Fetch current state
    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;
    let withdraw_info = WithdrawAccountInfo::new(ct_extension);

    // Generate proof data
    let withdraw_proof_data = WithdrawProofData::new(
        &withdraw_info,
        elgamal_keypair,
        ae_key,
        withdraw_amount,
    )?;

    let mut signatures = Vec::new();

    // Create context accounts for proofs
    let equality_proof_account = Keypair::new();
    let range_proof_account = Keypair::new();

    // Transaction 1: Upload equality proof
    let equality_instructions = create_equality_proof_context(
        &owner.pubkey(),
        &equality_proof_account.pubkey(),
        &withdraw_proof_data.equality_proof,
    )?;
    
    let recent_blockhash = client.get_latest_blockhash()?;
    let equality_tx = Transaction::new_signed_with_payer(
        &equality_instructions,
        Some(&owner.pubkey()),
        &[owner, &equality_proof_account],
        recent_blockhash,
    );
    signatures.push(client.send_and_confirm_transaction(&equality_tx)?);

    // Transaction 2: Upload range proof
    let range_instructions = create_range_proof_context(
        &owner.pubkey(),
        &range_proof_account.pubkey(),
        &withdraw_proof_data.range_proof,
    )?;
    
    let recent_blockhash = client.get_latest_blockhash()?;
    let range_tx = Transaction::new_signed_with_payer(
        &range_instructions,
        Some(&owner.pubkey()),
        &[owner, &range_proof_account],
        recent_blockhash,
    );
    signatures.push(client.send_and_confirm_transaction(&range_tx)?);

    // Transaction 3: Execute withdrawal referencing proof accounts
    let withdraw_instruction = withdraw_with_proof_accounts(
        &spl_token_2022::id(),
        &token_account,
        mint,
        withdraw_amount,
        decimals,
        withdraw_proof_data.new_decryptable_available_balance.into(),
        &owner.pubkey(),
        &equality_proof_account.pubkey(),
        &range_proof_account.pubkey(),
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let withdraw_tx = Transaction::new_signed_with_payer(
        &[withdraw_instruction],
        Some(&owner.pubkey()),
        &[owner],
        recent_blockhash,
    );
    signatures.push(client.send_and_confirm_transaction(&withdraw_tx)?);

    // Transaction 4: Close proof accounts
    let close_instructions = vec![
        close_context_account(&equality_proof_account.pubkey(), &owner.pubkey()),
        close_context_account(&range_proof_account.pubkey(), &owner.pubkey()),
    ];

    let recent_blockhash = client.get_latest_blockhash()?;
    let close_tx = Transaction::new_signed_with_payer(
        &close_instructions,
        Some(&owner.pubkey()),
        &[owner],
        recent_blockhash,
    );
    signatures.push(client.send_and_confirm_transaction(&close_tx)?);

    println!("Split proof withdrawal complete!");
    println!("  Transactions: {:?}", signatures);

    Ok(signatures)
}

// Helper stubs - see spl-token-2022 for full implementations
fn create_equality_proof_context(
    _payer: &Pubkey,
    _context_account: &Pubkey,
    _proof_data: &[u8],
) -> Result<Vec<solana_sdk::instruction::Instruction>, Box<dyn std::error::Error>> {
    todo!("See spl-token-2022 examples")
}

fn create_range_proof_context(
    _payer: &Pubkey,
    _context_account: &Pubkey,
    _proof_data: &[u8],
) -> Result<Vec<solana_sdk::instruction::Instruction>, Box<dyn std::error::Error>> {
    todo!("See spl-token-2022 examples")
}

fn withdraw_with_proof_accounts(
    _program_id: &Pubkey,
    _token_account: &Pubkey,
    _mint: &Pubkey,
    _amount: u64,
    _decimals: u8,
    _new_decryptable_balance: [u8; 36],
    _authority: &Pubkey,
    _equality_proof_account: &Pubkey,
    _range_proof_account: &Pubkey,
) -> Result<solana_sdk::instruction::Instruction, Box<dyn std::error::Error>> {
    todo!("See spl-token-2022 examples")
}

fn close_context_account(
    _context_account: &Pubkey,
    _destination: &Pubkey,
) -> solana_sdk::instruction::Instruction {
    todo!("See spl-token-2022 examples")
}

// =============================================================================
// WITHDRAWAL FLOW COMPARISON
// =============================================================================
//
// SIMPLE WITHDRAWAL (small amounts, inline proofs):
//   Transaction 1: Withdraw instruction with inline proofs
//   Total: 1 transaction
//
// SPLIT PROOF WITHDRAWAL (large amounts):
//   Transaction 1: Create + verify equality proof context
//   Transaction 2: Create + verify range proof context  
//   Transaction 3: Execute withdrawal
//   Transaction 4: Close context accounts
//   Total: 4 transactions
//
// =============================================================================

// =============================================================================
// POST-WITHDRAWAL STATE
// =============================================================================
//
// Before withdrawal:
//   public_balance: 0
//   confidential_available: 1000 (encrypted)
//
// After withdrawing 400:
//   public_balance: 400 (visible on-chain!)
//   confidential_available: 600 (encrypted)
//
// The withdrawn amount is now visible to everyone on-chain.
// Only the remaining confidential balance stays private.
// =============================================================================
