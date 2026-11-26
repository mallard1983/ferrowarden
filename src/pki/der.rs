//! A minimal, read-only DER reader for the two things `internal-certs` needs
//! from an existing CA certificate that rcgen cannot be told any other way:
//!
//! - the **subject**, as a list of (attribute, string type, text) entries, so
//!   the issuer name of a new certificate encodes byte for byte like the CA's
//!   subject (a path builder matches the two names by their bytes);
//! - the **subject key identifier**, so the authority key identifier of a new
//!   certificate equals it (OpenSSL, which the Bitwarden CLI uses through
//!   Node, rejects a chain whose two identifiers disagree).
//!
//! It reads only; it never validates a certificate (rustls-webpki does that),
//! and anything it does not understand is an error, not a guess.

/// A DER element: its tag byte, its content and its full encoding.
#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    full: &'a [u8],
}

/// Read one element from the front of `buf`; the rest follows it.
fn read_tlv(buf: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *buf.first()?;
    // Tags of 31 and above use a multi-byte form no certificate field here uses.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *buf.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for b in buf.get(2..2 + n)? {
            len = (len << 8) | usize::from(*b);
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    let full = buf.get(..end)?;
    Some((
        Tlv {
            tag,
            content: &full[header..],
            full,
        },
        &buf[end..],
    ))
}

/// The elements inside a constructed element's content.
fn children(content: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (tlv, next) = read_tlv(rest)?;
        out.push(tlv);
        rest = next;
    }
    Some(out)
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
const UTF8_STRING: u8 = 0x0c;
const PRINTABLE_STRING: u8 = 0x13;
const IA5_STRING: u8 = 0x16;
/// `[0]` (version) and `[3]` (extensions), explicit context tags.
const CTX_0: u8 = 0xa0;
const CTX_3: u8 = 0xa3;
/// The subjectKeyIdentifier extension, 2.5.29.14.
const OID_SKI: &[u8] = &[0x55, 0x1d, 0x0e];

/// How a subject string is encoded, which decides how it is written again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringKind {
    Utf8,
    Printable,
    Ia5,
}

/// One attribute of the subject name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameEntry {
    /// The attribute type OID as arcs, e.g. `[2, 5, 4, 3]` for the common name.
    pub oid: Vec<u64>,
    pub kind: StringKind,
    pub value: String,
}

/// What `internal-certs` reads from a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertParts {
    /// The issuer name, exactly as encoded (tag, length and content).
    pub issuer_raw: Vec<u8>,
    /// The subject name, exactly as encoded.
    pub subject_raw: Vec<u8>,
    /// The subject name, entry by entry.
    pub subject: Vec<NameEntry>,
    /// The subject key identifier, if the certificate has one.
    pub ski: Option<Vec<u8>>,
}

/// Decode an OID's content bytes into arcs.
fn oid_arcs(content: &[u8]) -> Option<Vec<u64>> {
    // A last byte with the continuation bit set is a truncated OID.
    if content.last()? & 0x80 != 0 {
        return None;
    }
    let mut arcs = Vec::new();
    let mut value: u64 = 0;
    for b in content {
        value = value.checked_mul(128)?.checked_add(u64::from(b & 0x7f))?;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let (a, rest) = match value {
                    0..=39 => (0, value),
                    40..=79 => (1, value - 40),
                    _ => (2, value - 80),
                };
                arcs.push(a);
                arcs.push(rest);
            } else {
                arcs.push(value);
            }
            value = 0;
        }
    }
    Some(arcs)
}

fn subject_entries(name: &Tlv<'_>) -> Result<Vec<NameEntry>, String> {
    let bad = || "the CA certificate's subject name cannot be read".to_string();
    let mut out = Vec::new();
    for rdn in children(name.content).ok_or_else(bad)? {
        if rdn.tag != SET {
            return Err(bad());
        }
        let atavs = children(rdn.content).ok_or_else(bad)?;
        // A multi-valued RDN is legal but unheard of in a CA name made by openssl.
        let [atav] = atavs.as_slice() else {
            return Err("the CA certificate's subject name has a multi-valued entry, which internal-certs does not support".into());
        };
        if atav.tag != SEQUENCE {
            return Err(bad());
        }
        let parts = children(atav.content).ok_or_else(bad)?;
        let [oid, value] = parts.as_slice() else {
            return Err(bad());
        };
        if oid.tag != OID {
            return Err(bad());
        }
        let kind = match value.tag {
            UTF8_STRING => StringKind::Utf8,
            PRINTABLE_STRING => StringKind::Printable,
            IA5_STRING => StringKind::Ia5,
            other => {
                return Err(format!(
                    "the CA certificate's subject name uses a string type (tag 0x{other:02x}) that internal-certs does not support"
                ))
            }
        };
        out.push(NameEntry {
            oid: oid_arcs(oid.content).ok_or_else(bad)?,
            kind,
            value: String::from_utf8(value.content.to_vec()).map_err(|_| bad())?,
        });
    }
    Ok(out)
}

/// Read the issuer, subject and subject key identifier of a DER certificate.
pub fn parse_cert(der: &[u8]) -> Result<CertParts, String> {
    let bad = || "not a readable X.509 certificate".to_string();
    let (cert, _) = read_tlv(der).ok_or_else(bad)?;
    if cert.tag != SEQUENCE {
        return Err(bad());
    }
    let (tbs, _) = read_tlv(cert.content).ok_or_else(bad)?;
    if tbs.tag != SEQUENCE {
        return Err(bad());
    }
    let mut fields = children(tbs.content).ok_or_else(bad)?.into_iter();
    let mut serial = fields.next().ok_or_else(bad)?;
    if serial.tag == CTX_0 {
        serial = fields.next().ok_or_else(bad)?; // skip the version
    }
    let _ = serial;
    let _signature_algorithm = fields.next().ok_or_else(bad)?;
    let issuer = fields.next().ok_or_else(bad)?;
    let _validity = fields.next().ok_or_else(bad)?;
    let subject = fields.next().ok_or_else(bad)?;
    let _spki = fields.next().ok_or_else(bad)?;
    if issuer.tag != SEQUENCE || subject.tag != SEQUENCE {
        return Err(bad());
    }

    let mut ski = None;
    for field in fields {
        if field.tag != CTX_3 {
            continue;
        }
        let (exts, _) = read_tlv(field.content).ok_or_else(bad)?;
        for ext in children(exts.content).ok_or_else(bad)? {
            let parts = children(ext.content).ok_or_else(bad)?;
            let (Some(oid), Some(value)) = (parts.first(), parts.last()) else {
                return Err(bad());
            };
            if oid.tag == OID && oid.content == OID_SKI && value.tag == OCTET_STRING {
                let (id, _) = read_tlv(value.content).ok_or_else(bad)?;
                if id.tag != OCTET_STRING {
                    return Err(bad());
                }
                ski = Some(id.content.to_vec());
            }
        }
    }

    Ok(CertParts {
        issuer_raw: issuer.full.to_vec(),
        subject_raw: subject.full.to_vec(),
        subject: subject_entries(&subject)?,
        ski,
    })
}
