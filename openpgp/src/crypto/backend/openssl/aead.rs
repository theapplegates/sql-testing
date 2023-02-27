//! Implementation of AEAD using OpenSSL cryptographic library.

use crate::{Error, Result};

use crate::crypto::aead::{Aead, CipherOp};
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

struct OpenSslContext {
    ctx: CipherCtx,
}

impl Aead for OpenSslContext {
    fn update(&mut self, ad: &[u8]) -> Result<()> {
        self.ctx.cipher_update(ad, None)?;
        Ok(())
    }

    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len() + self.digest_size());

        // SAFETY: Process completely one full chunk.  Since `update`
        // is not being called again with partial block info and the
        // cipher is finalized afterwards these two calls are safe.
        let size = unsafe { self.ctx.cipher_update_unchecked(src, Some(dst))? };
        unsafe { self.ctx.cipher_final_unchecked(&mut dst[size..])? };
        self.ctx.tag(&mut dst[src.len()..])?;
        Ok(())
    }

    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8], digest: &[u8]) -> Result<()> {
        // SAFETY: This condition makes the unsafe calls below correct.
        if dst.len() != src.len() {
            return Err(
                Error::InvalidArgument("src and dst need to be of the same length".into()).into(),
            );
        }

        // SAFETY: Process completely one full chunk.  Since `update`
        // is not being called again with partial block info and the
        // cipher is finalized afterwards these two calls are safe.
        let size = unsafe { self.ctx.cipher_update_unchecked(src, Some(dst))? };
        self.ctx.set_tag(digest)?;
        unsafe { self.ctx.cipher_final_unchecked(&mut dst[size..])? };
        Ok(())
    }

    fn digest_size(&self) -> usize {
        self.ctx.block_size()
    }
}

impl crate::seal::Sealed for OpenSslContext {}

impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        nonce: &[u8],
        op: CipherOp,
    ) -> Result<Box<dyn Aead>> {
        match self {
            AEADAlgorithm::OCB => {
                let cipher = match sym_algo {
                    SymmetricAlgorithm::AES128 => Cipher::aes_128_ocb(),
                    SymmetricAlgorithm::AES192 => Cipher::aes_192_ocb(),
                    SymmetricAlgorithm::AES256 => Cipher::aes_256_ocb(),
                    _ => return Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
                };
                let mut ctx = CipherCtx::new()?;
                match op {
                    CipherOp::Encrypt =>
                        ctx.encrypt_init(Some(cipher), Some(key), None)?,

                    CipherOp::Decrypt =>
                        ctx.decrypt_init(Some(cipher), Some(key), None)?,
                }
                // We have to set the IV length before supplying the
                // IV.  Otherwise, it will be silently truncated.
                ctx.set_iv_length(self.nonce_size()?)?;
                match op {
                    CipherOp::Encrypt =>
                        ctx.encrypt_init(None, None, Some(nonce))?,

                    CipherOp::Decrypt =>
                        ctx.decrypt_init(None, None, Some(nonce))?,
                }
                ctx.set_padding(false);
                Ok(Box::new(OpenSslContext {
                    ctx,
                }))
            }
            _ => Err(Error::UnsupportedAEADAlgorithm(*self).into()),
        }
    }
}
