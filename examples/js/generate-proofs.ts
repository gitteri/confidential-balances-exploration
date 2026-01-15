/**
 * ZK proof generation for confidential transfers
 * 
 * Demonstrates generating the three proof types required for transfers:
 * - Equality proof
 * - Ciphertext validity proof  
 * - Range proof
 */

import init, {
  ElGamalKeypair,
  ElGamalPubkey,
  PedersenOpening,
  PedersenCommitment,
  PubkeyValidityProofData,
  CiphertextCiphertextEqualityProofData,
  BatchedGroupedCiphertext3HandlesValidityProofData,
  BatchedRangeProofU128Data,
  ZeroCiphertextProofData,
} from '@solana/zk-sdk/web';

export async function generatePubkeyValidityProof(keypair: ElGamalKeypair) {
  await init();
  
  const proof = new PubkeyValidityProofData(keypair);
  proof.verify(); // Throws if invalid
  
  return proof.toBytes();
}

export async function generateZeroCiphertextProof(keypair: ElGamalKeypair) {
  await init();
  
  // Create ciphertext of zero
  const zeroCiphertext = keypair.pubkey().encryptU64(0n);
  
  const proof = new ZeroCiphertextProofData(keypair, zeroCiphertext);
  proof.verify();
  
  return proof.toBytes();
}

export interface TransferProofInputs {
  senderKeypair: ElGamalKeypair;
  recipientPubkey: ElGamalPubkey;
  auditorPubkey: ElGamalPubkey | null;
  transferAmount: bigint;
  currentBalance: bigint;
}

export interface TransferProofs {
  equality: Uint8Array;
  validity: Uint8Array;
  range: Uint8Array;
}

export async function generateTransferProofs(inputs: TransferProofInputs): Promise<TransferProofs> {
  await init();
  
  const { senderKeypair, recipientPubkey, auditorPubkey, transferAmount, currentBalance } = inputs;
  
  if (transferAmount > currentBalance) {
    throw new Error(`Insufficient balance: have ${currentBalance}, need ${transferAmount}`);
  }
  
  const remainingBalance = currentBalance - transferAmount;
  
  // Create Pedersen openings for both amounts
  const transferOpening = new PedersenOpening();
  const remainingOpening = new PedersenOpening();
  
  // Create commitments
  const transferCommitment = PedersenCommitment.withU64(transferAmount, transferOpening);
  const remainingCommitment = PedersenCommitment.withU64(remainingBalance, remainingOpening);
  
  // Encrypt for recipient (and auditor if present)
  const senderCiphertext = senderKeypair.pubkey().encryptWithOpening(transferAmount, transferOpening);
  const recipientCiphertext = recipientPubkey.encryptWithOpening(transferAmount, transferOpening);
  
  // 1. Equality proof: proves sender and recipient ciphertexts encrypt same amount
  const equalityProof = new CiphertextCiphertextEqualityProofData(
    senderKeypair,
    recipientPubkey,
    senderCiphertext,
    recipientCiphertext,
    transferOpening,
    transferAmount
  );
  equalityProof.verify();
  
  // 2. Ciphertext validity proof: proves ciphertexts are well-formed
  let validityProof: { toBytes(): Uint8Array; verify(): void };
  
  if (auditorPubkey) {
    validityProof = new BatchedGroupedCiphertext3HandlesValidityProofData(
      senderKeypair.pubkey(),
      recipientPubkey,
      auditorPubkey,
      transferAmount,
      transferOpening
    );
  } else {
    const { BatchedGroupedCiphertext2HandlesValidityProofData } = await import('@solana/zk-sdk/web');
    validityProof = new BatchedGroupedCiphertext2HandlesValidityProofData(
      senderKeypair.pubkey(),
      recipientPubkey,
      transferAmount,
      transferOpening
    );
  }
  validityProof.verify();
  
  // 3. Range proof: proves both amounts are in valid range [0, 2^64)
  const rangeProof = new BatchedRangeProofU128Data(
    [remainingCommitment, transferCommitment],
    new BigUint64Array([remainingBalance, transferAmount]),
    new Uint8Array([64, 64]), // Bit lengths must sum to 128
    [remainingOpening, transferOpening]
  );
  rangeProof.verify();
  
  return {
    equality: equalityProof.toBytes(),
    validity: validityProof.toBytes(),
    range: rangeProof.toBytes(),
  };
}

// Performance timing helper
export async function benchmarkProofGeneration(inputs: TransferProofInputs) {
  await init();
  
  console.log('Benchmarking proof generation...');
  
  const start = performance.now();
  const proofs = await generateTransferProofs(inputs);
  const elapsed = performance.now() - start;
  
  console.log(`Total time: ${elapsed.toFixed(0)}ms`);
  console.log(`Equality proof: ${proofs.equality.length} bytes`);
  console.log(`Validity proof: ${proofs.validity.length} bytes`);
  console.log(`Range proof: ${proofs.range.length} bytes`);
  
  return { proofs, elapsed };
}
