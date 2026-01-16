//! Common types for confidential transfer operations

use solana_sdk::signature::Signature;
use std::error::Error;

/// Result type for confidential transfer operations
pub type CtResult<T> = Result<T, Box<dyn Error>>;

/// Signature result for single transactions
pub type SigResult = CtResult<Signature>;

/// Signature result for multi-transaction operations
pub type MultiSigResult = CtResult<Vec<Signature>>;
