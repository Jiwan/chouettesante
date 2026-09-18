use anyhow::Result;
use openssl::{
    derive::Deriver,
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Public},
    rsa::{self, Rsa},
    symm::{Cipher, Crypter, Mode},
};
use thiserror::Error;

use super::constants;

pub(super) fn rsa_encrypted_size(plaintext_size: usize) -> usize {
    let rsa_key = Rsa::public_key_from_pem(constants::PUB_RSA_KEY.as_bytes()).unwrap();
    plaintext_size.next_multiple_of(rsa_key.size() as usize)
}

pub(super) fn rsa_encrypt(from: &[u8], to: &mut [u8]) -> usize {
    // From TUTK3rdRSAEncrypt in libTUTKGlobalAPIs.so.
    let rsa_key = Rsa::public_key_from_pem(constants::PUB_RSA_KEY.as_bytes()).unwrap();

    let modulus: usize = rsa_key.size() as usize;
    let padded_size = from.len().next_multiple_of(modulus);

    // Note that this padding strategy is horrifying.
    // It should be something like PKCS padding, but it is what the original code does.
    let mut padded_from = Vec::with_capacity(padded_size);
    padded_from.extend_from_slice(from);
    padded_from.resize(padded_size, 0);

    for (chunk_from, chunk_to) in padded_from.chunks(modulus).zip(to.chunks_mut(modulus)) {
        rsa_key
            .public_encrypt(chunk_from, chunk_to, rsa::Padding::NONE)
            .unwrap();
    }

    padded_size
}

pub(super) fn derive_aes_128_key(
    private_key: &EcKey<openssl::pkey::Private>,
    public_key: &PKey<Public>,
) -> Result<[u8; 16]> {
    // create AES key from ECDH shared secret (ECDH_compute_key equivalent)
    let my_pkey = PKey::from_ec_key(private_key.clone())?;
    let mut deriver = Deriver::new(&my_pkey)?;
    deriver.set_peer(&public_key)?;
    let shared_secret = deriver.derive_to_vec()?;
    let aes_key = &shared_secret[0..16];
    Ok(aes_key.try_into().unwrap())
}

pub(super) fn encrypt_aes_128_gcm(
    plaintext: &[u8],
    aad: &[u8],
    aes_key: [u8; 16],
    aes_iv: [u8; 12],
) -> Result<(Vec<u8>, Vec<u8>)> {
    // From TUTK3rdAESEncryptEx in libTUTKGlobalAPIs.so.
    // https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

    let cipher = Cipher::aes_128_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &aes_key, Some(&aes_iv))?;

    crypter.aad_update(aad)?;

    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let mut count = crypter.update(plaintext, &mut ciphertext)?;

    count += crypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count);

    let mut tag = vec![0; 16];
    crypter.get_tag(&mut tag)?;

    Ok((ciphertext, tag))
}

#[derive(Error, Debug)]
pub(super) enum DecryptError {
    #[error("AuthenticationFailed")]
    AuthenticationFailed,
}

pub(super) fn decrypt_aes_128_gcm(
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8],
    aes_key: [u8; 16],
    aes_iv: [u8; 12],
) -> Result<Vec<u8>, DecryptError> {
    // From TUTK3rdAESDecryptEx in libTUTKGlobalAPIs.so.
    // https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

    let cipher = Cipher::aes_128_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &aes_key, Some(&aes_iv)).unwrap();

    crypter.aad_update(aad).unwrap();
    crypter.set_tag(tag).unwrap();

    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = crypter.update(ciphertext, &mut plaintext).unwrap();

    match crypter.finalize(&mut plaintext[count..]) {
        Ok(n) => {
            count += n;
            plaintext.truncate(count);
            Ok(plaintext)
        }
        Err(_) => Err(DecryptError::AuthenticationFailed),
    }
}

pub(super) fn generate_ecdh_key() -> Result<EcKey<openssl::pkey::Private>> {
    // From TUTK3rdECDHCreateKeyPair in libTUTKGlobalAPIs.so:
    let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
    let group = EcGroup::from_curve_name(nid)?;
    let key = EcKey::generate(&group)?;
    Ok(key)
}
