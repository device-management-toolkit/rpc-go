/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/google/uuid"
)

// Intel Trusted Endpoint Provisioning (TEP, "TPP" in CSME firmware) runs over
// the UPID MEI client using feature code UPID_COMMAND_FEATURES_TEP. On the
// wire, structures are packed, enums are 4 bytes, and integers are
// little-endian.

// CommandFeatureTEP is UPID_COMMAND_FEATURES_TEP.
const CommandFeatureTEP uint8 = 1

// TEP command codes (UPID_TEP_PLATFORM_ID_FEATURE_COMMANDS).
const (
	TEPCommandGetTimeSyncNonce              uint8 = 1  // TEP_GET_TIME_SYNC_NONCE_CMD
	TEPCommandSetTimeCerts                  uint8 = 2  // TEP_SET_TIME_CERTS_CMD
	TEPCommandOwnershipVoucherRequest       uint8 = 3  // TEP_OWNERSHIP_VOUCHER_REQUEST_CMD
	TEPCommandSetOwnership                  uint8 = 4  // TEP_SET_OWNERSHIP_CMD
	TEPCommandGetVouchers                   uint8 = 5  // TEP_GET_VOUCHERS_CMD
	TEPCommandGetOwnershipState             uint8 = 6  // TEP_GET_OWNERSHIP_STATE_CMD
	TEPCommandOwnershipVoucherUpdateRequest uint8 = 7  // TEP_OWNERSHIP_VOUCHER_UPDATE_REQUEST_CMD
	TEPCommandOwnershipRemove               uint8 = 8  // TEP_OWNERSHIP_REMOVE_CMD
	TEPCommandGetCapabilities               uint8 = 9  // TEP_GET_CAPABILITIES_CMD
	TEPCommandGetAllVoucherIDs              uint8 = 10 // TEP_GET_ALL_VOUCHERS_ID_CMD
	TEPCommandGetVoucherStateByFeature      uint8 = 13 // TEP_GET_VOUCHER_STATE_BY_FEATURE_CMD
)

// TEP buffer sizes.
const (
	// TEPVoucherIDSize is the length of an ASCII UUID voucher/owner ID
	TEPVoucherIDSize = 36
	// TEPNonceSize is the size of req_id and csme_nonce
	TEPNonceSize = 20
	// TEPMaxJSONVoucherSize is TEP_MAX_JSON_VOUCHER_REQUEST
	TEPMaxJSONVoucherSize = 7400
	// TEPCertChainBufferSize is the certificate / OCSP response buffer size
	TEPCertChainBufferSize = 6000
	// TEPMaxCapabilityFeatures is the size of the TEP_GET_CAPABILITIES feature list (TPP_MAX_FEATURES)
	TEPMaxCapabilityFeatures = 2
	// TEPMaxChainEntries is the number of certificates/OCSP responses in TEP_SET_TIME_CERTS
	TEPMaxChainEntries = 4
	// TEPMetadataSize is the size of the voucher metadata field
	TEPMetadataSize = 256
	// TEPCredentialHashSize is the size of the owner credential hash field
	TEPCredentialHashSize = 64
	// TEPMaxVoucherFeatures is the number of feature slots in a voucher
	TEPMaxVoucherFeatures = 10
	// TEPMaxCertPolicies is the number of certificate policy slots in a voucher context
	TEPMaxCertPolicies = 10
	// TEPDistinguishedNameSize is the size of issuer/subject DN fields
	TEPDistinguishedNameSize = 256
	// TEPCertSerialNumberSize is the size of the certificate serial number field
	TEPCertSerialNumberSize = 20
	// TEPOrganizationNameSize is the size of the X520 organization name field
	TEPOrganizationNameSize = 64
	// CSMESignatureSize is the size of the CSME_SIGNATURE signature field
	CSMESignatureSize = 512
	// CSMESignatureMaxCerts is the number of certificates in a CSME_SIGNATURE chain
	CSMESignatureMaxCerts = 7
)

// TEPStatus is UPID_TEP_STATUS.
type TEPStatus uint32

const (
	TEPStatusSuccess           TEPStatus = 0
	TEPStatusTimeNotSet        TEPStatus = 1
	TEPStatusInvalidParameter  TEPStatus = 2
	TEPStatusNotAllowed        TEPStatus = 3
	TEPStatusBadSignature      TEPStatus = 4
	TEPStatusInvalidNonce      TEPStatus = 5
	TEPStatusInternalError     TEPStatus = 6
	TEPStatusInvalidCert       TEPStatus = 7
	TEPStatusInvalidVoucher    TEPStatus = 8
	TEPStatusOEMIDMismatch     TEPStatus = 9
	TEPStatusFeatureNotAllowed TEPStatus = 10
	TEPStatusInvalidCMS        TEPStatus = 11
)

// TEP status errors.
var (
	ErrTEPTimeNotSet        = errors.New("TEP time has not been set")
	ErrTEPInvalidParameter  = errors.New("TEP invalid parameter")
	ErrTEPNotAllowed        = errors.New("TEP operation not allowed")
	ErrTEPBadSignature      = errors.New("TEP signature verification failed")
	ErrTEPInvalidNonce      = errors.New("TEP CSME nonce is invalid or expired")
	ErrTEPInternalError     = errors.New("TEP internal error")
	ErrTEPInvalidCert       = errors.New("TEP certificate is revoked, expired or replayed")
	ErrTEPInvalidVoucher    = errors.New("TEP voucher does not match the stored voucher request")
	ErrTEPOEMIDMismatch     = errors.New("TEP OEM ID in signing certificate does not match platform")
	ErrTEPFeatureNotAllowed = errors.New("TEP signing certificate is not authorized for the requested feature")
	ErrTEPInvalidCMS        = errors.New("TEP CMS structure is invalid")
	ErrTEPUnknownStatus     = errors.New("TEP command failed with unknown status")
)

var tepStatusErrors = map[TEPStatus]error{
	TEPStatusTimeNotSet:        ErrTEPTimeNotSet,
	TEPStatusInvalidParameter:  ErrTEPInvalidParameter,
	TEPStatusNotAllowed:        ErrTEPNotAllowed,
	TEPStatusBadSignature:      ErrTEPBadSignature,
	TEPStatusInvalidNonce:      ErrTEPInvalidNonce,
	TEPStatusInternalError:     ErrTEPInternalError,
	TEPStatusInvalidCert:       ErrTEPInvalidCert,
	TEPStatusInvalidVoucher:    ErrTEPInvalidVoucher,
	TEPStatusOEMIDMismatch:     ErrTEPOEMIDMismatch,
	TEPStatusFeatureNotAllowed: ErrTEPFeatureNotAllowed,
	TEPStatusInvalidCMS:        ErrTEPInvalidCMS,
}

// Err returns nil for TEPStatusSuccess, otherwise the matching sentinel error.
// Unrecognized values wrap ErrTEPUnknownStatus.
func (s TEPStatus) Err() error {
	if s == TEPStatusSuccess {
		return nil
	}

	if err, ok := tepStatusErrors[s]; ok {
		return err
	}

	return fmt.Errorf("%w: 0x%08x", ErrTEPUnknownStatus, uint32(s))
}

// TEPVoucherFormat is the binary voucher request format.
type TEPVoucherFormat uint32

// TEPVoucherFormatCMSJSON is the only defined format: a JSON voucher signed with CMS.
const TEPVoucherFormatCMSJSON TEPVoucherFormat = 1

// TEPAssertion is the voucher assertion type.
type TEPAssertion uint32

const (
	TEPAssertionVerified      TEPAssertion = 0
	TEPAssertionVettedClaimed TEPAssertion = 1
)

func (a TEPAssertion) String() string {
	switch a {
	case TEPAssertionVerified:
		return "verified"
	case TEPAssertionVettedClaimed:
		return "vetted-claimed"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(a))
	}
}

// TEPCredentialType is the kind of credential in a voucher: the certificate
// the owner credential hash refers to (voucher version 1.0), or the kind of
// policy being configured (voucher version 2.0).
type TEPCredentialType uint32

const (
	TEPCredentialTypeDomainCA TEPCredentialType = 0
	TEPCredentialTypeLeaf     TEPCredentialType = 1
	TEPCredentialTypeCapMgmt  TEPCredentialType = 2
)

// String returns the conventional lower-case name for the value.
func (c TEPCredentialType) String() string {
	switch c {
	case TEPCredentialTypeDomainCA:
		return "domain-ca-cert"
	case TEPCredentialTypeLeaf:
		return "leaf-cert"
	case TEPCredentialTypeCapMgmt:
		return "cap-mgmt"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(c))
	}
}

// TEPHashAlgorithm is the voucher hash_algo field. Byte 0 holds the
// algorithm (the TPP_SIGNING_MECHANISM_TYPE enum). For voucher version 2.0
// policies that are not hashed (algorithm TEPHashNone), byte 1 holds the
// PolicyConfig length in 8-byte units; see NewTEPPolicyConfigAttr.
type TEPHashAlgorithm uint32

const (
	TEPHashNone   TEPHashAlgorithm = 0
	TEPHashSHA256 TEPHashAlgorithm = 2
	TEPHashSHA384 TEPHashAlgorithm = 3
	TEPHashSHA224 TEPHashAlgorithm = 4
	TEPHashSHA512 TEPHashAlgorithm = 5
)

const (
	hashAlgorithmMask  = 0xFF
	policyLenShift     = 8
	policyLenUnit      = 8
	maxPolicyLenInUnit = TEPCredentialHashSize / policyLenUnit
)

// ErrInvalidPolicyConfigLength is returned when a PolicyConfig length cannot be encoded.
var ErrInvalidPolicyConfigLength = errors.New("TEP PolicyConfig length must be a multiple of 8 between 8 and 64 bytes")

// NewTEPPolicyConfigAttr returns the hash_algo value for an unhashed
// (algorithm "none") voucher version 2.0 PolicyConfig of the given length.
func NewTEPPolicyConfigAttr(policyConfigLen int) (TEPHashAlgorithm, error) {
	if policyConfigLen <= 0 || policyConfigLen%policyLenUnit != 0 || policyConfigLen/policyLenUnit > maxPolicyLenInUnit {
		return 0, fmt.Errorf("%w: got %d", ErrInvalidPolicyConfigLength, policyConfigLen)
	}

	return TEPHashNone | TEPHashAlgorithm(policyConfigLen/policyLenUnit)<<policyLenShift, nil
}

// Algorithm returns the algorithm in byte 0, without any encoded length.
func (h TEPHashAlgorithm) Algorithm() TEPHashAlgorithm {
	return h & hashAlgorithmMask
}

// Size returns the number of meaningful bytes in the credential hash /
// PolicyConfig field: the digest length, or for TEPHashNone the encoded
// PolicyConfig length. It returns 0 for an unknown algorithm.
func (h TEPHashAlgorithm) Size() int {
	switch h.Algorithm() {
	case TEPHashNone:
		return int(min((h>>policyLenShift)&hashAlgorithmMask, maxPolicyLenInUnit)) * policyLenUnit
	case TEPHashSHA224:
		return sha256.Size224
	case TEPHashSHA256:
		return sha256.Size
	case TEPHashSHA384:
		return sha512.Size384
	case TEPHashSHA512:
		return sha512.Size
	default:
		return 0
	}
}

// String returns the conventional lower-case name for the value.
func (h TEPHashAlgorithm) String() string {
	switch h.Algorithm() {
	case TEPHashNone:
		return "none"
	case TEPHashSHA224:
		return "SHA-224"
	case TEPHashSHA256:
		return "SHA-256"
	case TEPHashSHA384:
		return "SHA-384"
	case TEPHashSHA512:
		return "SHA-512"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(h.Algorithm()))
	}
}

// TEPOwnershipStatus is the state of an ownership voucher.
type TEPOwnershipStatus uint32

const (
	TEPOwnershipNotSet    TEPOwnershipStatus = 0
	TEPOwnershipRequested TEPOwnershipStatus = 1
	TEPOwnershipActive    TEPOwnershipStatus = 2
	TEPOwnershipExpired   TEPOwnershipStatus = 3
	TEPOwnershipSuspended TEPOwnershipStatus = 4
	TEPOwnershipUpdate    TEPOwnershipStatus = 5
)

// String returns the conventional lower-case name for the value.
func (s TEPOwnershipStatus) String() string {
	switch s {
	case TEPOwnershipNotSet:
		return "undefined"
	case TEPOwnershipRequested:
		return "requested"
	case TEPOwnershipActive:
		return "active"
	case TEPOwnershipExpired:
		return "expired"
	case TEPOwnershipSuspended:
		return "suspended"
	case TEPOwnershipUpdate:
		return "update"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(s))
	}
}

// TEPSignatureMechanism identifies the algorithm of a CSME_SIGNATURE. It
// shares TPP_SIGNING_MECHANISM_TYPE with TEPHashAlgorithm.
type TEPSignatureMechanism uint32

// TEPSignatureECDSA384SHA384 is TPP_SIGN_ECDSA384_WITH_SHA384, the only
// mechanism CSME uses for TEP responses on PTL.
const TEPSignatureECDSA384SHA384 TEPSignatureMechanism = 3

// TEPFeature is TEP_ENUM_FEATURES, the UINT8 feature ID used in the
// TEP_GET_CAPABILITIES_CMD feature list.
type TEPFeature uint8

const (
	// TEPFeatureAny may appear in stored vouchers; it cannot be requested.
	TEPFeatureAny TEPFeature = 100
	// TEPFeatureAMT is provisioned with a voucher version 1.0 owner credential.
	TEPFeatureAMT TEPFeature = 101
	// TEPFeatureOEM1 is reserved for OEM use (voucher version 1.0).
	TEPFeatureOEM1 TEPFeature = 150
	// TEPFeatureCapMgmt is SoC capability management (voucher version 2.0, NVL+).
	TEPFeatureCapMgmt TEPFeature = 160
)

// String returns the feature's display name.
func (f TEPFeature) String() string {
	switch f {
	case TEPFeatureAny:
		return "Any"
	case TEPFeatureAMT:
		return "AMT"
	case TEPFeatureOEM1:
		return "OEM"
	case TEPFeatureCapMgmt:
		return "Capability Management"
	default:
		return fmt.Sprintf("Feature %d", uint8(f))
	}
}

// Certificate policy OID arcs (2.16.840.1.113741.1.2.5.y) reported in
// TEPOwnershipContext.CertPolicies for the Ownership Service certificate.
const (
	TEPPolicyVettedClaimed uint16 = 6
	TEPPolicyVerified      uint16 = 7
	TEPPolicyOEMID         uint16 = 8
	TEPPolicyOverride      uint16 = 9
)

// tepFeatureOIDArc is x in 2.16.840.1.113741.1.2.x.y for TEP feature OIDs.
const tepFeatureOIDArc = 5

// OID returns the feature's OID (2.16.840.1.113741.1.2.5.<feature>) as carried
// in vouchers and TEP_GET_VOUCHER_STATE_BY_FEATURE_CMD.
func (f TEPFeature) OID() TEPOID {
	return TEPOID{X: tepFeatureOIDArc, Y: uint16(f)}
}

// TEPOID is INTEL_TEP_OID: Intel OID 2.16.840.1.113741.1.2.X.Y encoded as two
// UINT16s. Feature lists and certificate policies use this encoding (sending
// the bare feature number to TEP_GET_VOUCHER_STATE_BY_FEATURE_CMD is rejected
// with TEP_INVALID_PARAMETER on PTL CSME 21).
type TEPOID struct {
	X uint16
	Y uint16
}

// IsZero reports whether the OID slot is unused.
func (o TEPOID) IsZero() bool {
	return o == TEPOID{}
}

func (o TEPOID) String() string {
	return fmt.Sprintf("2.16.840.1.113741.1.2.%d.%d", o.X, o.Y)
}

// TEPVersion is the voucher version (tpp_version). Major 1 is an owner
// credential voucher (AMT/OEM features), major 2 is a capability management
// policy voucher.
type TEPVersion struct {
	Major uint16
	Minor uint16
}

var (
	TEPVoucherVersion1 = TEPVersion{Major: 1}
	TEPVoucherVersion2 = TEPVersion{Major: 2}
)

func (v TEPVersion) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// TEPVoucherID is an ASCII UUID as carried in TEP messages (TEP_VOUCHER_ID).
type TEPVoucherID [TEPVoucherIDSize]byte

// ErrInvalidVoucherID is returned when a voucher or owner ID is not a canonical UUID.
var ErrInvalidVoucherID = errors.New("invalid TEP voucher ID")

// NewTEPVoucherID converts a canonical 36-character UUID string into a TEPVoucherID.
func NewTEPVoucherID(id string) (TEPVoucherID, error) {
	var v TEPVoucherID

	if len(id) != TEPVoucherIDSize {
		return v, fmt.Errorf("%w: %q must be %d characters", ErrInvalidVoucherID, id, TEPVoucherIDSize)
	}

	if _, err := uuid.Parse(id); err != nil {
		return v, fmt.Errorf("%w: %q: %w", ErrInvalidVoucherID, id, err)
	}

	copy(v[:], id)

	return v, nil
}

// String returns the ID as a string, trimming any trailing NUL padding.
func (v TEPVoucherID) String() string {
	return strings.TrimRight(string(v[:]), "\x00")
}

// IsZero reports whether the ID is unset (all NUL).
func (v TEPVoucherID) IsZero() bool {
	return v == TEPVoucherID{}
}

// TEPBinaryVoucherRequest is TEP_BINARY_VOUCHER_REQUEST (564 bytes). It is the
// payload of both TEP_OWNERSHIP_VOUCHER_REQUEST_CMD and
// TEP_OWNERSHIP_VOUCHER_UPDATE_REQUEST_CMD. CreatedOnUTC and UPID are filled
// in by CSME and may be left zero.
type TEPBinaryVoucherRequest struct {
	Format                TEPVoucherFormat
	Version               TEPVersion
	VoucherID             TEPVoucherID
	Assertion             TEPAssertion
	OwnerID               TEPVoucherID
	Metadata              [TEPMetadataSize]byte
	CreatedOnUTC          uint32
	ExpiresOnUTC          uint32
	UPID                  [UPIDSize]byte
	CredentialType        TEPCredentialType
	HashAlgorithm         TEPHashAlgorithm
	OwnerCredentialHash   [TEPCredentialHashSize]byte
	OwnershipExpiresOnUTC uint32
	PrevVoucherID         TEPVoucherID
	Features              [TEPMaxVoucherFeatures]TEPOID
}

// TEPOwnershipContext is TEP_OWNERSHIP_CONTEXT (tpp_ownership_context, 1138
// bytes packed) as returned by TEP_GET_OWNERSHIP_STATE_CMD and
// TEP_GET_VOUCHER_STATE_BY_FEATURE_CMD. IssuerSubjectDN and CertSubjectDN are
// DER-encoded X.509 Names; use IssuerName and SubjectName to decode them.
type TEPOwnershipContext struct {
	OwnershipStatus          TEPOwnershipStatus
	OwnershipActiveTimestamp uint32
	VoucherID                TEPVoucherID
	Assertion                TEPAssertion
	OwnerID                  TEPVoucherID
	Metadata                 [TEPMetadataSize]byte
	CreatedOnUTC             uint32
	ExpiresOnUTC             uint32
	CredentialType           TEPCredentialType
	HashAlgorithm            TEPHashAlgorithm
	OwnerCredentialHash      [TEPCredentialHashSize]byte
	OwnershipExpiresOnUTC    uint32
	PrevVoucherID            TEPVoucherID
	Features                 [TEPMaxVoucherFeatures]TEPOID
	IssuerSubjectDN          [TEPDistinguishedNameSize]byte
	CertSerialNumber         [TEPCertSerialNumberSize]byte
	CertSubjectDN            [TEPDistinguishedNameSize]byte
	X520OrgName              [TEPOrganizationNameSize]byte
	CertPolicies             [TEPMaxCertPolicies]TEPOID
	OEMID                    uint16
}

// IssuerName decodes IssuerSubjectDN, the issuer of the Ownership Service certificate.
func (c *TEPOwnershipContext) IssuerName() (pkix.Name, error) {
	return decodeDN(c.IssuerSubjectDN[:])
}

// SubjectName decodes CertSubjectDN, the subject of the Ownership Service certificate.
func (c *TEPOwnershipContext) SubjectName() (pkix.Name, error) {
	return decodeDN(c.CertSubjectDN[:])
}

// SerialNumber returns the Ownership Service certificate serial number, a
// big-endian integer stored with trailing zero padding.
func (c *TEPOwnershipContext) SerialNumber() *big.Int {
	return new(big.Int).SetBytes(bytes.TrimRight(c.CertSerialNumber[:], "\x00"))
}

// FeatureOIDs returns the populated entries of Features.
func (c *TEPOwnershipContext) FeatureOIDs() []TEPOID {
	return populatedOIDs(c.Features[:])
}

// PolicyOIDs returns the populated entries of CertPolicies.
func (c *TEPOwnershipContext) PolicyOIDs() []TEPOID {
	return populatedOIDs(c.CertPolicies[:])
}

// VoucherVersion infers the voucher version, which CSME does not store:
// vouchers for the AMT, OEM or any feature are version 1.0, all others 2.0.
func (c *TEPOwnershipContext) VoucherVersion() TEPVersion {
	for _, oid := range c.FeatureOIDs() {
		if oid.X != tepFeatureOIDArc {
			continue
		}

		switch TEPFeature(oid.Y) {
		case TEPFeatureAny, TEPFeatureAMT, TEPFeatureOEM1:
			return TEPVoucherVersion1
		case TEPFeatureCapMgmt:
			// version 2.0 feature; keep looking for a version 1.0 one
		}
	}

	return TEPVoucherVersion2
}

// Credential returns the meaningful bytes of OwnerCredentialHash (the owner
// credential hash for version 1.0, the PolicyConfig for version 2.0).
func (c *TEPOwnershipContext) Credential() []byte {
	return c.OwnerCredentialHash[:c.HashAlgorithm.Size()]
}

// ErrInvalidDN is returned when a distinguished name field is not valid DER.
var ErrInvalidDN = errors.New("invalid TEP distinguished name")

// decodeDN decodes a zero-padded DER X.509 Name. An all-zero field is an empty name.
func decodeDN(b []byte) (pkix.Name, error) {
	var name pkix.Name

	if len(bytes.TrimRight(b, "\x00")) == 0 {
		return name, nil
	}

	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(b, &rdn); err != nil {
		return name, fmt.Errorf("%w: %w", ErrInvalidDN, err)
	}

	name.FillFromRDNSequence(&rdn)

	return name, nil
}

func populatedOIDs(oids []TEPOID) []TEPOID {
	var out []TEPOID

	for _, oid := range oids {
		if oid.X == 0 || oid.Y == 0 {
			break
		}

		out = append(out, oid)
	}

	return out
}

// CSMESignature is CSME_SIGNATURE. A Timestamp of 0 means TEP time has not
// been set yet.
//
// As verified on PTL CSME 21, the signature is ECDSA P-384 over the SHA-384
// digest of Status || [response data] || SignatureMechanism || Timestamp
// (note: mechanism before timestamp, the reverse of the struct order), stored
// as raw big-endian r || s in the first 96 bytes of Signature. It is made with
// the CSME TEP IDevID key, the leaf of the chain in Certificates.
type CSMESignature struct {
	Timestamp            uint32
	SignatureMechanism   TEPSignatureMechanism
	Signature            [CSMESignatureSize]byte
	LengthOfCertificates [CSMESignatureMaxCerts]uint16
	Certificates         [TEPCertChainBufferSize]byte
}

// CertificateChain splits Certificates into individual DER certificates
// using LengthOfCertificates, stopping at the first zero length.
func (s *CSMESignature) CertificateChain() ([][]byte, error) {
	return splitChain(s.LengthOfCertificates[:], s.Certificates[:])
}

// ErrInvalidCertChain is returned when certificate lengths overrun their buffer.
var ErrInvalidCertChain = errors.New("invalid TEP certificate chain")

// ErrCSMESignatureInvalid is returned when a CSME_SIGNATURE does not verify.
var ErrCSMESignatureInvalid = errors.New("CSME signature is invalid")

// p384ScalarSize is the size of an ECDSA P-384 r or s value.
const p384ScalarSize = 48

// Verify checks the signature over signedData against the leaf certificate
// of the signature's own chain. It does not validate that chain up to an
// Intel root; the server receiving the response must do that.
func (s *CSMESignature) Verify(signedData []byte) error {
	if s.SignatureMechanism != TEPSignatureECDSA384SHA384 {
		return fmt.Errorf("%w: unsupported signature mechanism %d", ErrCSMESignatureInvalid, s.SignatureMechanism)
	}

	chain, err := s.CertificateChain()
	if err != nil {
		return err
	}

	if len(chain) == 0 {
		return fmt.Errorf("%w: no certificates", ErrCSMESignatureInvalid)
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return fmt.Errorf("%w: leaf certificate: %w", ErrCSMESignatureInvalid, err)
	}

	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return fmt.Errorf("%w: leaf key is not ECDSA P-384", ErrCSMESignatureInvalid)
	}

	digest := sha512.Sum384(signedData)
	r := new(big.Int).SetBytes(s.Signature[:p384ScalarSize])
	sv := new(big.Int).SetBytes(s.Signature[p384ScalarSize : 2*p384ScalarSize])

	if !ecdsa.Verify(pub, digest[:], r, sv) {
		return ErrCSMESignatureInvalid
	}

	return nil
}

// splitChain slices buf into consecutive entries of the given lengths,
// stopping at the first zero length.
func splitChain(lengths []uint16, buf []byte) ([][]byte, error) {
	var chain [][]byte

	offset := 0

	for i, l := range lengths {
		if l == 0 {
			break
		}

		end := offset + int(l)
		if end > len(buf) {
			return nil, fmt.Errorf("%w: entry %d (%d bytes at offset %d) exceeds %d-byte buffer", ErrInvalidCertChain, i, l, offset, len(buf))
		}

		chain = append(chain, buf[offset:end])
		offset = end
	}

	return chain, nil
}
