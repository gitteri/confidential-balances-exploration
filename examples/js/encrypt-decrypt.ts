/**
 * Basic encryption/decryption operations with ElGamal and AES
 */

import init, {
  ElGamalKeypair,
  ElGamalPubkey,
  AeKey,
  PedersenOpening,
  PedersenCommitment,
  GroupedElGamalCiphertext2Handles,
} from '@solana/zk-sdk/web';

export async function demonstrateEncryption() {
  await init();
  
  // Generate keypairs for sender and recipient
  const senderKeypair = new ElGamalKeypair();
  const recipientKeypair = new ElGamalKeypair();
  
  const amount = 1000n;
  
  // Single-recipient encryption
  const ciphertext = senderKeypair.pubkey().encryptU64(amount);
  const decrypted = senderKeypair.secret().decrypt(ciphertext);
  console.log('Single encryption - Amount matches:', decrypted === amount);
  
  // Multi-recipient encryption (both parties can decrypt)
  const groupedCiphertext = GroupedElGamalCiphertext2Handles.encrypt(
    senderKeypair.pubkey(),
    recipientKeypair.pubkey(),
    amount
  );
  
  const senderDecrypted = groupedCiphertext.decrypt(senderKeypair.secret(), 0);
  const recipientDecrypted = groupedCiphertext.decrypt(recipientKeypair.secret(), 1);
  
  console.log('Grouped encryption - Sender can decrypt:', senderDecrypted === amount);
  console.log('Grouped encryption - Recipient can decrypt:', recipientDecrypted === amount);
  
  // AES encryption for balance display
  const aeKey = new AeKey();
  const aeCiphertext = aeKey.encrypt(amount);
  const aeDecrypted = aeKey.decrypt(aeCiphertext);
  console.log('AES encryption - Amount matches:', aeDecrypted === amount);
  
  // Pedersen commitment (for range proofs)
  const opening = new PedersenOpening();
  const commitment = PedersenCommitment.withU64(amount, opening);
  console.log('Commitment created:', commitment.toBytes().length, 'bytes');
  
  return {
    senderKeypair,
    recipientKeypair,
    groupedCiphertext,
  };
}

export async function encryptForTransfer(
  senderPubkey: ElGamalPubkey,
  recipientPubkey: ElGamalPubkey,
  auditorPubkey: ElGamalPubkey | null,
  amount: bigint
) {
  await init();
  
  if (auditorPubkey) {
    // 3-handle encryption: sender, recipient, auditor
    const { GroupedElGamalCiphertext3Handles } = await import('@solana/zk-sdk/web');
    return GroupedElGamalCiphertext3Handles.encrypt(
      senderPubkey,
      recipientPubkey,
      auditorPubkey,
      amount
    );
  }
  
  // 2-handle encryption: sender, recipient
  return GroupedElGamalCiphertext2Handles.encrypt(
    senderPubkey,
    recipientPubkey,
    amount
  );
}
