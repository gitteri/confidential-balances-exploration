/**
 * ElGamal keypair derivation from wallet signature
 * 
 * Confidential balances require deterministic key derivation so users
 * can recover their encryption keys from their wallet.
 */

import init, { ElGamalKeypair, AeKey } from '@solana/zk-sdk/web';

const ELGAMAL_SEED_MESSAGE = 'ElGamalSecretKey';
const AE_KEY_SEED_MESSAGE = 'AeKey';

interface WalletAdapter {
  publicKey: { toBytes(): Uint8Array };
  signMessage(message: Uint8Array): Promise<Uint8Array>;
}

export async function deriveConfidentialKeys(wallet: WalletAdapter) {
  await init();
  
  const encoder = new TextEncoder();
  
  // Derive ElGamal keypair from wallet signature
  const elgamalSeed = await wallet.signMessage(
    encoder.encode(ELGAMAL_SEED_MESSAGE)
  );
  const elgamalKeypair = ElGamalKeypair.fromSeed(elgamalSeed.slice(0, 32));
  
  // Derive AES key from wallet signature
  const aeSeed = await wallet.signMessage(
    encoder.encode(AE_KEY_SEED_MESSAGE)
  );
  const aeKey = AeKey.fromSeed(aeSeed.slice(0, 16));
  
  return { elgamalKeypair, aeKey };
}

// Usage with @solana/wallet-adapter
export async function deriveFromWalletAdapter(wallet: WalletAdapter) {
  const { elgamalKeypair, aeKey } = await deriveConfidentialKeys(wallet);
  
  console.log('ElGamal pubkey:', Buffer.from(elgamalKeypair.pubkey().toBytes()).toString('hex'));
  console.log('AE key derived successfully');
  
  return { elgamalKeypair, aeKey };
}
