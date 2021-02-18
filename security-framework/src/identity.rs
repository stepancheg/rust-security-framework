//! Identity support.

use core_foundation::base::TCFType;
use security_framework_sys::base::SecIdentityRef;
use security_framework_sys::identity::*;
use std::fmt;
use std::ptr;

use crate::base::Result;
use crate::certificate::SecCertificate;
use crate::cvt;
use crate::import_export::Pkcs12ImportOptions;
use crate::key::SecKey;

declare_TCFType! {
    /// A type representing an identity.
    ///
    /// Identities are a certificate paired with the corresponding private key.
    SecIdentity, SecIdentityRef
}
impl_TCFType!(SecIdentity, SecIdentityRef, SecIdentityGetTypeID);

unsafe impl Sync for SecIdentity {}
unsafe impl Send for SecIdentity {}

impl fmt::Debug for SecIdentity {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = fmt.debug_struct("SecIdentity");
        if let Ok(cert) = self.certificate() {
            builder.field("certificate", &cert);
        }
        if let Ok(key) = self.private_key() {
            builder.field("private_key", &key);
        }
        builder.finish()
    }
}

impl SecIdentity {
    /// Imports identities from PKCS #12 file.
    ///
    /// All other data from that file is discarded.
    ///
    /// This is a simple shortcut for the most common operation.
    pub fn from_pkcs12(pkcs12_der: &[u8], password: &str) -> Result<Vec<SecIdentity>> {
        let imported_identities = Pkcs12ImportOptions::new()
            .passphrase(password)
            .import(pkcs12_der)?;
        Ok(imported_identities
            .into_iter()
            .flat_map(|identity| identity.identity)
            .collect())
    }

    /// Returns the certificate corresponding to this identity.
    pub fn certificate(&self) -> Result<SecCertificate> {
        unsafe {
            let mut certificate = ptr::null_mut();
            cvt(SecIdentityCopyCertificate(self.0, &mut certificate))?;
            Ok(SecCertificate::wrap_under_create_rule(certificate))
        }
    }

    /// Returns the private key corresponding to this identity.
    pub fn private_key(&self) -> Result<SecKey> {
        unsafe {
            let mut key = ptr::null_mut();
            cvt(SecIdentityCopyPrivateKey(self.0, &mut key))?;
            Ok(SecKey::wrap_under_create_rule(key))
        }
    }
}

#[cfg(test)]
mod test {
    use super::SecIdentity;

    #[test]
    fn identity_has_send_bound() {
        fn assert_send<T: Send>() {}
        assert_send::<SecIdentity>();
    }

    #[test]
    fn sec_identity_from_pkcs12() {
        let pkcs12_der = include_bytes!("../test/server.p12");
        let identities = SecIdentity::from_pkcs12(pkcs12_der, "password123").unwrap();
        assert_eq!(1, identities.len());
    }
}
