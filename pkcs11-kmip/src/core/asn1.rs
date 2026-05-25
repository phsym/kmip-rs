use der::{Sequence, ValueOrd, asn1::OctetStringRef};
use spki::AlgorithmIdentifierRef;

/// ```asn1
/// DigestInfo ::= SEQUENCE {
/// digestAlgorithm DigestAlgorithmIdentifier,
/// digest Digest }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct DigestInfoRef<'a> {
    /// the algorithm.
    pub algorithm: AlgorithmIdentifierRef<'a>,

    /// the digest
    pub digest: OctetStringRef<'a>,
}
