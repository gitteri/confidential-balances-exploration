/**
 * On-chain proof verification using @solana-program/zk-elgamal-proof
 * 
 * Demonstrates creating context accounts and verifying proofs on-chain.
 */

import {
  createSolanaRpc,
  generateKeyPairSigner,
  createTransactionMessage,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  appendTransactionMessageInstructions,
  signAndSendTransactionMessageWithSigners,
  pipe,
} from '@solana/kit';
import {
  verifyBatchedRangeProofU128,
  verifyCiphertextCommitmentEquality,
  verifyBatchedGroupedCiphertext3HandlesValidity,
  closeContextStateProof,
} from '@solana-program/zk-elgamal-proof';

const RPC_URL = 'https://api.devnet.solana.com';

interface VerifyProofsInput {
  equalityProof: Uint8Array;
  validityProof: Uint8Array;
  rangeProof: Uint8Array;
}

export async function verifyProofsOnChain(proofs: VerifyProofsInput) {
  const rpc = createSolanaRpc(RPC_URL);
  const payer = await generateKeyPairSigner();
  
  // Create context accounts for each proof
  const equalityAccount = await generateKeyPairSigner();
  const validityAccount = await generateKeyPairSigner();
  const rangeAccount = await generateKeyPairSigner();
  
  console.log('Requesting airdrop for payer...');
  // In production, payer would have SOL already
  
  // Build verification instructions
  const equalityIxs = await verifyCiphertextCommitmentEquality({
    rpc,
    payer,
    proofData: proofs.equalityProof,
    contextState: {
      contextAccount: equalityAccount,
      authority: payer.address,
    },
  });
  
  const validityIxs = await verifyBatchedGroupedCiphertext3HandlesValidity({
    rpc,
    payer,
    proofData: proofs.validityProof,
    contextState: {
      contextAccount: validityAccount,
      authority: payer.address,
    },
  });
  
  const rangeIxs = await verifyBatchedRangeProofU128({
    rpc,
    payer,
    proofData: proofs.rangeProof,
    contextState: {
      contextAccount: rangeAccount,
      authority: payer.address,
    },
  });
  
  // Send verification transactions
  const { value: blockhash } = await rpc.getLatestBlockhash().send();
  
  // Transaction 1: Equality proof
  const equalityTx = pipe(
    createTransactionMessage({ version: 0 }),
    tx => setTransactionMessageFeePayer(payer.address, tx),
    tx => setTransactionMessageLifetimeUsingBlockhash(blockhash, tx),
    tx => appendTransactionMessageInstructions(equalityIxs, tx),
  );
  const equalitySig = await signAndSendTransactionMessageWithSigners(equalityTx);
  console.log('Equality proof verified:', equalitySig);
  
  // Transaction 2: Validity proof  
  const validityTx = pipe(
    createTransactionMessage({ version: 0 }),
    tx => setTransactionMessageFeePayer(payer.address, tx),
    tx => setTransactionMessageLifetimeUsingBlockhash(blockhash, tx),
    tx => appendTransactionMessageInstructions(validityIxs, tx),
  );
  const validitySig = await signAndSendTransactionMessageWithSigners(validityTx);
  console.log('Validity proof verified:', validitySig);
  
  // Transaction 3: Range proof
  const rangeTx = pipe(
    createTransactionMessage({ version: 0 }),
    tx => setTransactionMessageFeePayer(payer.address, tx),
    tx => setTransactionMessageLifetimeUsingBlockhash(blockhash, tx),
    tx => appendTransactionMessageInstructions(rangeIxs, tx),
  );
  const rangeSig = await signAndSendTransactionMessageWithSigners(rangeTx);
  console.log('Range proof verified:', rangeSig);
  
  return {
    contextAccounts: {
      equality: equalityAccount.address,
      validity: validityAccount.address,
      range: rangeAccount.address,
    },
    signatures: {
      equality: equalitySig,
      validity: validitySig,
      range: rangeSig,
    },
  };
}

export async function closeProofAccounts(
  contextAccounts: { equality: string; validity: string; range: string },
  payer: Awaited<ReturnType<typeof generateKeyPairSigner>>
) {
  const rpc = createSolanaRpc(RPC_URL);
  const { value: blockhash } = await rpc.getLatestBlockhash().send();
  
  const closeIxs = [
    closeContextStateProof({
      contextState: contextAccounts.equality as any,
      authority: payer,
      destination: payer.address,
    }),
    closeContextStateProof({
      contextState: contextAccounts.validity as any,
      authority: payer,
      destination: payer.address,
    }),
    closeContextStateProof({
      contextState: contextAccounts.range as any,
      authority: payer,
      destination: payer.address,
    }),
  ];
  
  const closeTx = pipe(
    createTransactionMessage({ version: 0 }),
    tx => setTransactionMessageFeePayer(payer.address, tx),
    tx => setTransactionMessageLifetimeUsingBlockhash(blockhash, tx),
    tx => appendTransactionMessageInstructions(closeIxs, tx),
  );
  
  const sig = await signAndSendTransactionMessageWithSigners(closeTx);
  console.log('Context accounts closed:', sig);
  
  return sig;
}
