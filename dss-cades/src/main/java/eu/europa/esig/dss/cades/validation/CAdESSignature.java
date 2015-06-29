/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades.validation;

import static eu.europa.esig.dss.OID.id_aa_ets_archiveTimestampV2;
import static eu.europa.esig.dss.OID.id_aa_ets_archiveTimestampV3;
import static eu.europa.esig.dss.x509.ArchiveTimestampType.CAdES_V2;
import static eu.europa.esig.dss.x509.ArchiveTimestampType.CAdES_v3;
import static eu.europa.esig.dss.x509.TimestampType.ARCHIVE_TIMESTAMP;
import static eu.europa.esig.dss.x509.TimestampType.CONTENT_TIMESTAMP;
import static eu.europa.esig.dss.x509.TimestampType.SIGNATURE_TIMESTAMP;
import static eu.europa.esig.dss.x509.TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP;
import static eu.europa.esig.dss.x509.TimestampType.VALIDATION_DATA_TIMESTAMP;
import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response;
import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_basic;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_contentTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificate;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificateV2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.esf.SigPolicyQualifiers;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ContentIdentifier;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttCertValidityPeriod;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.signature.CadesLevelBaselineLTATimestampExtractor;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CAdESCertificateSource;
import eu.europa.esig.dss.validation.CRLRef;
import eu.europa.esig.dss.validation.CandidatesForSigningCertificate;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.CertificateValidity;
import eu.europa.esig.dss.validation.CertifiedRole;
import eu.europa.esig.dss.validation.CommitmentType;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.OCSPRef;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.TimestampReference;
import eu.europa.esig.dss.validation.TimestampReferenceCategory;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.ArchiveTimestampType;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignatureForm;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;
import eu.europa.esig.dss.x509.ocsp.OfflineOCSPSource;

/**
 * CAdES Signature class helper
 */

public class CAdESSignature extends DefaultAdvancedSignature {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignature.class);

	private static final Date JANUARY_1950 = DSSUtils.getUtcDate(1950, 1, 1);

	private static final Date JANUARY_2050 = DSSUtils.getUtcDate(2050, 1, 1);

	private final CMSSignedData cmsSignedData;

	private final SignerInformation signerInformation;

	private CAdESCertificateSource certSource;

	/**
	 * The reference to the signing certificate. If the signing certificate is
	 * an input provided by the DA then getSigningCer MUST be called.
	 */
	private CertificateValidity signingCertificateValidity;

	/**
	 * This list represents all digest algorithms used to calculate the digest
	 * values of certificates.
	 */
	private Set<DigestAlgorithm> usedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();

	/**
	 * This id identifies the signature, it is calculated on the signing time if
	 * present and on the certificate.
	 */
	private String signatureId;

	/**
	 * It's only used to keep the same signature id between cades and pades
	 * signature. (PAdESSignature should extend XAdESSignature!)
	 */
	private Date padesSigningTime = null;

	/**
	 * Cached list of the Signing Certificate Timestamp References.
	 */
	private List<TimestampReference> signingCertificateTimestampReferences;

	/**
	 * @param data
	 *            byte array representing CMSSignedData
	 * @throws org.bouncycastle.cms.CMSException
	 */
	public CAdESSignature(final byte[] data) throws CMSException {

		this(new CMSSignedData(data), new CertificatePool());
	}

	/**
	 * @param data
	 *            byte array representing CMSSignedData
	 * @param certPool
	 *            can be null
	 * @throws org.bouncycastle.cms.CMSException
	 */
	public CAdESSignature(final byte[] data, final CertificatePool certPool) throws CMSException {

		this(new CMSSignedData(data), certPool);
	}

	/**
	 * The default constructor for CAdESSignature.
	 *
	 * @param cms
	 *            CMSSignedData
	 * @param certPool
	 *            can be null
	 */
	public CAdESSignature(final CMSSignedData cms, final CertificatePool certPool) {

		this(cms, getFirstSignerInformation(cms), certPool);
	}

	/**
	 * @param cmsSignedData
	 *            CMSSignedData
	 * @param signerInformation
	 *            an expanded SignerInfo block from a CMS Signed message
	 */
	public CAdESSignature(final CMSSignedData cmsSignedData, final SignerInformation signerInformation) {
		this(cmsSignedData, signerInformation, new CertificatePool());
	}

	/**
	 * The default constructor for CAdESSignature.
	 *
	 * @param cmsSignedData
	 *            CMSSignedData
	 * @param signerInformation
	 *            an expanded SignerInfo block from a CMS Signed message
	 * @param certPool
	 *            can be null
	 */
	public CAdESSignature(final CMSSignedData cmsSignedData, final SignerInformation signerInformation, final CertificatePool certPool) {

		super(certPool);
		this.cmsSignedData = cmsSignedData;
		this.signerInformation = signerInformation;
	}

	/**
	 * This is convenience method. To be used only internally!
	 *
	 * @param padesSigningTime
	 *            PAdES signing time
	 */
	public void setPadesSigningTime(final Date padesSigningTime) {
		this.padesSigningTime = padesSigningTime;
	}

	/**
	 * Returns the first {@code SignerInformation} extracted from {@code CMSSignedData}.
	 *
	 * @param cms
	 *            CMSSignedData
	 * @return returns {@code SignerInformation}
	 */
	private static SignerInformation getFirstSignerInformation(final CMSSignedData cms) {

		final Collection signers = cms.getSignerInfos().getSigners();
		if (signers.size() > 1) {
			LOG.warn("!!! The framework handles only one signer (SignerInformation) !!!");
		}
		final SignerInformation signerInformation = (SignerInformation) signers.iterator().next();
		return signerInformation;
	}

	/**
	 * This method returns the certificate pool used by this instance to handle
	 * encapsulated certificates.
	 *
	 * @return the certificate pool associated with the signature
	 */
	public CertificatePool getCertPool() {
		return certPool;
	}

	@Override
	public SignatureForm getSignatureForm() {

		return SignatureForm.CAdES;
	}

	@Override
	public CAdESCertificateSource getCertificateSource() {

		if (certSource == null) {

			certSource = new CAdESCertificateSource(cmsSignedData, signerInformation, certPool);
		}
		return certSource;
	}

	@Override
	public OfflineCRLSource getCRLSource() {

		if (offlineCRLSource == null) {
			try {
				offlineCRLSource = new CAdESCRLSource(cmsSignedData, signerInformation);
			} catch (Exception e) {
				// When error in computing or in format of the algorithm: just
				// continues (will try to get online information)
				LOG.warn("Error in computing or in format of the algorithm: just continue...", e);
			}
		}
		return offlineCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {

		if (offlineOCSPSource == null) {
			offlineOCSPSource = new CAdESOCSPSource(cmsSignedData, signerInformation);
		}
		return offlineOCSPSource;
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 * 5.6.3 Signature Verification Process
	 * ...the public key from the first certificate identified in the sequence
	 * of certificate identifiers from SigningCertificate shall be the key used
	 * to verify the digital signature.
	 *
	 * @return
	 */
	@Override
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate() {

		if (candidatesForSigningCertificate != null) {

			return candidatesForSigningCertificate;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("Searching the signing certificate...");
		}
		candidatesForSigningCertificate = new CandidatesForSigningCertificate();

		final Collection<CertificateToken> keyInfoCertificates = getCertificateSource().getKeyInfoCertificates();
		final SignerId signerId = signerInformation.getSID();
		for (final CertificateToken certificateToken : keyInfoCertificates) {

			final CertificateValidity certificateValidity = new CertificateValidity(certificateToken);
			candidatesForSigningCertificate.add(certificateValidity);

			final X509CertificateHolder x509CertificateHolder = certificateToken.getX509CertificateHolder();
			final boolean match = signerId.match(x509CertificateHolder);
			if (match) {

				this.signingCertificateValidity = certificateValidity;
				break;
			}
		}
		if (signingCertificateValidity == null) {
			LOG.warn("Signing certificate not found: " + signerId.getIssuer() + " " + signerId.getSerialNumber());
		} else if (!verifySignedReferencesToSigningCertificate()) {
			LOG.warn("There is no valid signed reference to the signing certificate: " + signingCertificateValidity.getCertificateToken().getAbbreviation());
		}
		return candidatesForSigningCertificate;
	}

	private boolean verifySignedReferencesToSigningCertificate() {

		final IssuerSerial signingTokenIssuerSerial = DSSUtils.getIssuerSerial(signingCertificateValidity.getCertificateToken());
		final BigInteger signingTokenSerialNumber = signingTokenIssuerSerial.getSerial().getValue();
		final GeneralNames signingTokenIssuerName = signingTokenIssuerSerial.getIssuer();

		final AttributeTable signedAttributes = getSignedAttributes(signerInformation);
		final Attribute signingCertificateAttributeV1 = signedAttributes.get(id_aa_signingCertificate);
		if (signingCertificateAttributeV1 != null) {

			signingCertificateValidity.setAttributePresent(true);
			verifySigningCertificateV1(signingTokenSerialNumber, signingTokenIssuerName, signingCertificateAttributeV1);
			return true;
		}
		final Attribute signingCertificateAttributeV2 = signedAttributes.get(id_aa_signingCertificateV2);
		if (signingCertificateAttributeV2 != null) {

			signingCertificateValidity.setAttributePresent(true);
			verifySigningCertificateV2(signingTokenSerialNumber, signingTokenIssuerName, signingCertificateAttributeV2);
			return true;
		}
		return false;
	}

	private void verifySigningCertificateV1(final BigInteger signingTokenSerialNumber, final GeneralNames signingTokenIssuerName, final Attribute signingCertificateAttributeV1) {

		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;
		final byte[] signingTokenCertHash = DSSUtils.digest(digestAlgorithm, signingCertificateValidity.getCertificateToken().getEncoded());
		if (LOG.isDebugEnabled()) {
			LOG.debug("Candidate Certificate Hash {} with algorithm {}", Hex.encodeHexString(signingTokenCertHash), digestAlgorithm.getName());
		}

		final ASN1Set attrValues = signingCertificateAttributeV1.getAttrValues();
		for (int ii = 0; ii < attrValues.size(); ii++) {

			final ASN1Encodable asn1Encodable = attrValues.getObjectAt(ii);
			final SigningCertificate signingCertificate = SigningCertificate.getInstance(asn1Encodable);
			final ESSCertID[] essCertIDs = signingCertificate.getCerts();
			for (final ESSCertID essCertID : essCertIDs) {

				final byte[] certHash = essCertID.getCertHash();
				signingCertificateValidity.setDigestPresent(true);
				if (LOG.isDebugEnabled()) {
					LOG.debug("Found Certificate Hash in signingCertificateAttributeV1 {} with algorithm {}", Hex.encodeHexString(certHash), digestAlgorithm.getName());
				}
				final IssuerSerial issuerSerial = essCertID.getIssuerSerial();
				final boolean match = verifySigningCertificateReferences(signingTokenSerialNumber, signingTokenIssuerName, signingTokenCertHash, certHash, issuerSerial);
				if (match) {
					return;
				}
				LOG.warn("RFC 2634: The first certificate identified in the sequence of certificate identifiers MUST be the certificate used to verify the signature.");
			}
		}
	}

	private void verifySigningCertificateV2(final BigInteger signingTokenSerialNumber, final GeneralNames signingTokenIssuerName, final Attribute signingCertificateAttributeV2) {

		final ASN1Set attrValues = signingCertificateAttributeV2.getAttrValues();

		DigestAlgorithm lastDigestAlgorithm = null;
		byte[] signingTokenCertHash = null;

		for (int ii = 0; ii < attrValues.size(); ii++) {

			final ASN1Encodable asn1Encodable = attrValues.getObjectAt(ii);
			final SigningCertificateV2 signingCertificateAttribute = SigningCertificateV2.getInstance(asn1Encodable);
			if (signingCertificateAttribute == null) {
				LOG.warn("SigningCertificateV2 attribute is not well defined!");
				continue;
			}
			final ESSCertIDv2[] essCertIDv2s = signingCertificateAttribute.getCerts();
			for (final ESSCertIDv2 essCertIDv2 : essCertIDv2s) {

				final String algorithmId = essCertIDv2.getHashAlgorithm().getAlgorithm().getId();
				final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(algorithmId);
				signingCertificateValidity.setDigestAlgorithm(digestAlgorithm);
				if (digestAlgorithm != lastDigestAlgorithm) {

					signingTokenCertHash = DSSUtils.digest(digestAlgorithm, signingCertificateValidity.getCertificateToken().getEncoded());
					if (LOG.isDebugEnabled()) {
						LOG.debug("Candidate Certificate Hash {} with algorithm {}", Hex.encodeHexString(signingTokenCertHash), digestAlgorithm.getName());
					}
					lastDigestAlgorithm = digestAlgorithm;
				}
				final byte[] certHash = essCertIDv2.getCertHash();
				signingCertificateValidity.setDigestPresent(true);
				if (LOG.isDebugEnabled()) {
					LOG.debug("Found Certificate Hash in SigningCertificateV2 {} with algorithm {}", Hex.encodeHexString(certHash), digestAlgorithm.getName());
				}
				final IssuerSerial issuerSerial = essCertIDv2.getIssuerSerial();
				final boolean match = verifySigningCertificateReferences(signingTokenSerialNumber, signingTokenIssuerName, signingTokenCertHash, certHash, issuerSerial);
				if (match) {
					return;
				}
				LOG.warn("RFC 5035: The first certificate identified in the sequence of certificate identifiers MUST be the certificate used to verify the signature.");
			}
		}
	}

	private boolean verifySigningCertificateReferences(final BigInteger signingTokenSerialNumber, final GeneralNames signingTokenIssuerName, final byte[] signingTokenCertHash,
			final byte[] certHash, final IssuerSerial issuerSerial) {

		signingCertificateValidity.setDigest(Base64.encodeBase64String(signingTokenCertHash));
		final boolean hashEqual = Arrays.equals(certHash, signingTokenCertHash);
		signingCertificateValidity.setDigestEqual(hashEqual);

		if (issuerSerial != null) {

			final BigInteger serialNumber = issuerSerial.getSerial().getValue();
			boolean serialNumberEqual = serialNumber.equals(signingTokenSerialNumber);
			signingCertificateValidity.setSerialNumberEqual(serialNumberEqual);
		}
		if (issuerSerial != null) {

			final GeneralNames issuerName = issuerSerial.getIssuer();

			final String canonicalizedIssuerName = getCanonicalizedName(issuerName);
			final String canonicalizedSigningTokenIssuerName = getCanonicalizedName(signingTokenIssuerName);

			// DOES NOT WORK IN ALL CASES:
			// issuerNameEqual = issuerName.equals(signingTokenIssuerName);
			boolean issuerNameEqual = canonicalizedIssuerName.equals(canonicalizedSigningTokenIssuerName);
			signingCertificateValidity.setDistinguishedNameEqual(issuerNameEqual);
		}
		// Validation of the hash is sufficient
		return hashEqual;
	}

	/**
	 * This method can be removed the simple IssuerSerial verification can be
	 * performed. In fact the hash verification is sufficient.
	 *
	 * @param generalNames
	 * @return
	 */
	static String getCanonicalizedName(final GeneralNames generalNames) {

		final GeneralName[] names = generalNames.getNames();
		final TreeMap<String, String> treeMap = new TreeMap<String, String>();
		for (final GeneralName name : names) {

			final String ldapString = String.valueOf(name.getName());
			LOG.debug("ldapString to canonicalize: {} ", ldapString);
			try {

				final LdapName ldapName = new LdapName(ldapString);
				final List<Rdn> rdns = ldapName.getRdns();
				for (final Rdn rdn : rdns) {

					treeMap.put(rdn.getType().toLowerCase(), String.valueOf(rdn.getValue()).toLowerCase());
				}
			} catch (InvalidNameException e) {
				throw new DSSException(e);
			}
		}
		final StringBuilder stringBuilder = new StringBuilder();
		for (final Map.Entry<String, String> entry : treeMap.entrySet()) {

			stringBuilder.append(entry.getKey()).append('=').append(entry.getValue()).append('|');
		}
		final String canonicalizedName = stringBuilder.toString();
		LOG.debug("canonicalizedName: {} ", canonicalizedName);
		return canonicalizedName;
	}

	@Override
	public List<CertificateToken> getCertificates() {
		return getCertificateSource().getCertificates();
	}

	/**
	 * 31 ETSI TS 101 733 V2.2.1 (2013-04)
	 * 5.8.1 signature-policy-identifier The present document mandates that for
	 * CAdES-EPES, a reference to the signature policy is included in the
	 * signedData. This reference is explicitly identified. A signature policy
	 * defines the rules for creation and validation of an electronic signature,
	 * and is included as a signed attribute with every Explicit Policy-based
	 * Electronic Signature. The signature-policy-identifier shall be a signed
	 * attribute.
	 * The following object identifier identifies the
	 * signature-policy-identifier attribute: ... id-aa-ets-sigPolicyId OBJECT
	 * IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
	 * pkcs9(9) smime(16) id-aa(2) 15 } signature-policy-identifier attribute
	 * values have ASN.1 type SignaturePolicyIdentifier: ...
	 * SignaturePolicyIdentifier ::=CHOICE{ ...... signaturePolicyId .........
	 * SignaturePolicyId, ...... signaturePolicyImplied ....
	 * SignaturePolicyImplied -- not used in this version}
	 * ... SignaturePolicyId ::= SEQUENCE { ...... sigPolicyId .........
	 * SigPolicyId, ...... sigPolicyHash ....... SigPolicyHash, ......
	 * sigPolicyQualifiers . SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo
	 * OPTIONAL}
	 * ... SignaturePolicyImplied ::= NULL
	 * NOTE: {@code SignaturePolicyImplied} -- not used in this version
	 *
	 * @return
	 */
	@Override
	public SignaturePolicy getPolicyId() {

		final AttributeTable attributes = signerInformation.getSignedAttributes();
		if (attributes == null) {
			return null;
		}

		final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
		if (attribute == null) {
			return null;
		}

		final ASN1Encodable attrValue = attribute.getAttrValues().getObjectAt(0);
		if (attrValue instanceof DERNull) {
			return null;
		}

		final SignaturePolicyId sigPolicy = SignaturePolicyId.getInstance(attrValue);
		if (sigPolicy == null) {
			return null;
		}

		final String policyId = sigPolicy.getSigPolicyId().getId();
		final SignaturePolicy signaturePolicy = new SignaturePolicy(policyId);

		final OtherHashAlgAndValue hashAlgAndValue = sigPolicy.getSigPolicyHash();

		final AlgorithmIdentifier digestAlgorithmIdentifier = hashAlgAndValue.getHashAlgorithm();
		final String digestAlgorithmOID = digestAlgorithmIdentifier.getAlgorithm().getId();
		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(digestAlgorithmOID);
		signaturePolicy.setDigestAlgorithm(digestAlgorithm);

		final ASN1OctetString digestValue = hashAlgAndValue.getHashValue();
		final byte[] digestValueBytes = digestValue.getOctets();
		final String policyDigestHexValue = DSSUtils.toHex(digestValueBytes);
		signaturePolicy.setDigestValue(policyDigestHexValue);

		final SigPolicyQualifiers sigPolicyQualifiers = sigPolicy.getSigPolicyQualifiers();
		if (sigPolicyQualifiers == null) {

			return signaturePolicy;
		}
		for (int ii = 0; ii < sigPolicyQualifiers.size(); ii++) {

			final SigPolicyQualifierInfo policyQualifierInfo = sigPolicyQualifiers.getInfoAt(ii);
			final ASN1ObjectIdentifier policyQualifierInfoId = policyQualifierInfo.getSigPolicyQualifierId();
			final String policyQualifierInfoValue = policyQualifierInfo.getSigQualifier().toString();

			if (PKCSObjectIdentifiers.id_spq_ets_unotice.equals(policyQualifierInfoId)) {

				signaturePolicy.setNotice(policyQualifierInfoValue);
			} else if (PKCSObjectIdentifiers.id_spq_ets_uri.equals(policyQualifierInfoId)) {

				signaturePolicy.setUrl(policyQualifierInfoValue);
			} else {
				LOG.error("Unknown signature policy qualifier id: " + policyQualifierInfoId + " with value: " + policyQualifierInfoValue);
			}
		}
		return signaturePolicy;
	}

	@Override
	public Date getSigningTime() {

		final AttributeTable attributes = signerInformation.getSignedAttributes();
		if (attributes == null) {
			return null;
		}

		final Attribute attr = attributes.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime);
		if (attr == null) {

			return null;
		}
		final ASN1Set attrValues = attr.getAttrValues();
		final ASN1Encodable attrValue = attrValues.getObjectAt(0);
		final Date signingDate;
		if (attrValue instanceof ASN1UTCTime) {
			signingDate = DSSASN1Utils.toDate((ASN1UTCTime) attrValue);
		} else if (attrValue instanceof Time) {
			signingDate = ((Time) attrValue).getDate();
		} else if (attrValue instanceof ASN1GeneralizedTime) {
			signingDate = DSSASN1Utils.toDate((ASN1GeneralizedTime) attrValue);
		} else {
			signingDate = null;
		}
		if (signingDate != null) {
			/*
			 * RFC 3852 [4] states that "dates between January 1, 1950 and
			 * December 31, 2049 (inclusive) must be encoded as UTCTime. Any
			 * dates with year values before 1950 or after 2049 must be encoded
			 * as GeneralizedTime".
			 */
			if (!(signingDate.before(JANUARY_1950) && signingDate.after(JANUARY_2050))) {
				// must be ASN1UTCTime
				if (!(attrValue instanceof ASN1UTCTime)) {
					LOG.error(
							"RFC 3852 states that dates between January 1, 1950 and December 31, 2049 (inclusive) must be encoded as UTCTime. Any dates with year values before 1950 or after 2049 must be encoded as GeneralizedTime. Date found is {} encoded as {}",
							signingDate.toString(), attrValue.getClass());
					return null;
				}
			}
			return signingDate;
		}
		if (LOG.isErrorEnabled()) {
			LOG.error("Error when reading signing time. Unrecognized " + attrValue.getClass());
		}
		return null;
	}

	/**
	 * @return the cmsSignedData
	 */
	public CMSSignedData getCmsSignedData() {

		return cmsSignedData;
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {

		final AttributeTable attributes = signerInformation.getSignedAttributes();
		if (attributes == null) {

			return null;
		}
		Attribute signatureProductionPlaceAttr = attributes.get(PKCSObjectIdentifiers.id_aa_ets_signerLocation);
		if (signatureProductionPlaceAttr == null) {

			return null;
		}

		final ASN1Encodable asn1Encodable = signatureProductionPlaceAttr.getAttrValues().getObjectAt(0);
		SignerLocation signerLocation = null;
		try {
			signerLocation = SignerLocation.getInstance(asn1Encodable);
		} catch (Exception e) {
			LOG.error(e.getMessage(), e);
		}
		if (signerLocation == null) {
			return null;
		}
		final SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
		final DERUTF8String countryName = signerLocation.getCountryName();
		if (countryName != null) {

			signatureProductionPlace.setCountryName(countryName.getString());
		}
		final DERUTF8String localityName = signerLocation.getLocalityName();
		if (localityName != null) {

			signatureProductionPlace.setCity(localityName.getString());
		}
		final StringBuilder address = new StringBuilder();
		final ASN1Sequence seq = signerLocation.getPostalAddress();
		if (seq != null) {

			for (int ii = 0; ii < seq.size(); ii++) {

				if (seq.getObjectAt(ii) instanceof DEROctetString) {
					if (address.length() > 0) {
						address.append(" / ");
					}
					// TODO: getOctets returns an array
					address.append(new String(((DEROctetString) seq.getObjectAt(ii)).getOctets()));
				} else if (seq.getObjectAt(ii) instanceof DERUTF8String) {

					if (address.length() > 0) {
						address.append(" / ");
					}
					final DERUTF8String derutf8String = (DERUTF8String) seq.getObjectAt(ii);
					address.append(derutf8String.getString());
				}
			}
		}
		signatureProductionPlace.setAddress(address.toString());
		// This property is not used in CAdES version of signature
		// signatureProductionPlace.setStateOrProvince(stateOrProvince);
		return signatureProductionPlace;
	}

	@Override
	public CommitmentType getCommitmentTypeIndication() {

		final AttributeTable attributes = signerInformation.getSignedAttributes();
		if (attributes == null) {

			return null;
		}
		final Attribute commitmentTypeIndicationAttribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_commitmentType);
		if (commitmentTypeIndicationAttribute != null) {

			try {

				final ASN1Set attrValues = commitmentTypeIndicationAttribute.getAttrValues();
				final int size = attrValues.size();
				if (size > 0) {

					final CommitmentType commitmentType = new CommitmentType();
					for (int ii = 0; ii < size; ii++) {

						final DERSequence derSequence = (DERSequence) attrValues.getObjectAt(ii);
						final CommitmentTypeIndication commitmentTypeIndication = CommitmentTypeIndication.getInstance(derSequence);
						final ASN1ObjectIdentifier commitmentTypeId = commitmentTypeIndication.getCommitmentTypeId();
						commitmentType.addIdentifier(commitmentTypeId.getId());
					}
					return commitmentType;
				}
			} catch (Exception e) {
				throw new DSSException("Error when dealing with CommitmentTypeIndication!", e);
			}
		}
		return null;
	}

	@Override
	public String[] getClaimedSignerRoles() {

		final AttributeTable attributes = signerInformation.getSignedAttributes();
		if (attributes == null) {
			return null;
		}
		final Attribute id_aa_ets_signerAttr = attributes.get(PKCSObjectIdentifiers.id_aa_ets_signerAttr);
		if (id_aa_ets_signerAttr == null) {
			return null;
		}
		final ASN1Set attrValues = id_aa_ets_signerAttr.getAttrValues();
		final ASN1Encodable attrValue = attrValues.getObjectAt(0);
		try {

			final SignerAttribute signerAttr = SignerAttribute.getInstance(attrValue);
			if (signerAttr == null) {
				return null;
			}
			final List<String> claimedRoles = new ArrayList<String>();
			final Object[] signerAttrValues = signerAttr.getValues();
			for (final Object signerAttrValue : signerAttrValues) {

				if (!(signerAttrValue instanceof org.bouncycastle.asn1.x509.Attribute[])) {

					continue;
				}
				final org.bouncycastle.asn1.x509.Attribute[] signerAttrValueArray = (org.bouncycastle.asn1.x509.Attribute[]) signerAttrValue;
				for (final org.bouncycastle.asn1.x509.Attribute claimedRole : signerAttrValueArray) {

					final ASN1Encodable[] attrValues1 = claimedRole.getAttrValues().toArray();
					for (final ASN1Encodable asn1Encodable : attrValues1) {
						if (asn1Encodable instanceof ASN1String) {
							ASN1String asn1String = (ASN1String) asn1Encodable;
							final String s = asn1String.getString();
							claimedRoles.add(s);
						}
					}
				}
			}
			final String[] strings = claimedRoles.toArray(new String[claimedRoles.size()]);
			return strings;
		} catch (Exception e) {

			throw new DSSException("Error when dealing with claimed signer roles: [" + attrValue.toString() + "]", e);
		}
	}

	@Override
	public List<CertifiedRole> getCertifiedSignerRoles() {

		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		if (signedAttributes == null) {
			return null;
		}

		final Attribute id_aa_ets_signerAttr = signedAttributes.get(PKCSObjectIdentifiers.id_aa_ets_signerAttr);
		if (id_aa_ets_signerAttr == null) {
			return null;
		}
		final ASN1Set attrValues = id_aa_ets_signerAttr.getAttrValues();
		final ASN1Encodable asn1EncodableAttrValue = attrValues.getObjectAt(0);
		try {

			final SignerAttribute signerAttr = SignerAttribute.getInstance(asn1EncodableAttrValue);
			if (signerAttr == null) {
				return null;
			}
			List<CertifiedRole> roles = null;
			final Object[] signerAttrValues = signerAttr.getValues();
			for (final Object signerAttrValue : signerAttrValues) {

				if (signerAttrValue instanceof AttributeCertificate) {

					if (roles == null) {

						roles = new ArrayList<CertifiedRole>();
					}
					final AttributeCertificate attributeCertificate = (AttributeCertificate) signerAttrValue;
					final AttributeCertificateInfo acInfo = attributeCertificate.getAcinfo();
					final AttCertValidityPeriod attrCertValidityPeriod = acInfo.getAttrCertValidityPeriod();
					final ASN1Sequence attributes = acInfo.getAttributes();
					for (int ii = 0; ii < attributes.size(); ii++) {

						final ASN1Encodable objectAt = attributes.getObjectAt(ii);
						final org.bouncycastle.asn1.x509.Attribute attribute = org.bouncycastle.asn1.x509.Attribute.getInstance(objectAt);
						final ASN1Set attrValues1 = attribute.getAttrValues();
						DERSequence derSequence = (DERSequence) attrValues1.getObjectAt(0);
						RoleSyntax roleSyntax = RoleSyntax.getInstance(derSequence);
						CertifiedRole certifiedRole = new CertifiedRole();
						certifiedRole.setRole(roleSyntax.getRoleNameAsString());
						certifiedRole.setNotBefore(DSSASN1Utils.toDate(attrCertValidityPeriod.getNotBeforeTime()));
						certifiedRole.setNotAfter(DSSASN1Utils.toDate(attrCertValidityPeriod.getNotAfterTime()));
						roles.add(certifiedRole);
					}
				}
			}
			return roles;
		} catch (Exception e) {

			throw new DSSException("Error when dealing with certified signer roles: [" + asn1EncodableAttrValue.toString() + "]", e);
		}
	}

	@Override
	public byte[] getContentTimestampData(final TimestampToken timestampToken) {

		final ContentInfo contentInfo = cmsSignedData.toASN1Structure();
		final SignedData signedData = SignedData.getInstance(contentInfo.getContent());

		ContentInfo content = signedData.getEncapContentInfo();
		if ((content == null) || (content.getContent() == null)) {

			// Detached signatures have either no encapContentInfo in
			// signedData, or it exists but has no eContent
			final byte[] originalDocumentBytes = getOriginalDocumentBytes();
			if (originalDocumentBytes != null) {

				return originalDocumentBytes;
			} else {
				LOG.error("No original data provided for content timestamp!");
				return DSSUtils.EMPTY_BYTE_ARRAY;
			}
		} // else {

		ASN1OctetString octet = (ASN1OctetString) content.getContent();
		return octet.getOctets();
	}

	@Override
	public List<TimestampToken> getContentTimestamps() {

		if (contentTimestamps == null) {
			makeTimestampTokens();
		}
		return contentTimestamps;
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() throws RuntimeException {

		if (signatureTimestamps == null) {
			makeTimestampTokens();
		}
		return signatureTimestamps;
	}

	@Override
	public List<TimestampToken> getTimestampsX1() {

		if (sigAndRefsTimestamps == null) {
			makeTimestampTokens();
		}
		return sigAndRefsTimestamps;
	}

	@Override
	public List<TimestampToken> getTimestampsX2() {

		if (refsOnlyTimestamps == null) {
			makeTimestampTokens();
		}
		return refsOnlyTimestamps;
	}

	@Override
	public List<TimestampToken> getArchiveTimestamps() {

		if (archiveTimestamps == null) {
			makeTimestampTokens();
		}
		return archiveTimestamps;
	}

	private void makeTimestampTokens() {

		contentTimestamps = createTimestamps(id_aa_ets_contentTimestamp, CONTENT_TIMESTAMP, null);
		signatureTimestamps = createTimestamps(id_aa_signatureTimeStampToken, SIGNATURE_TIMESTAMP, null);
		refsOnlyTimestamps = createTimestamps(id_aa_ets_certCRLTimestamp, VALIDATION_DATA_REFSONLY_TIMESTAMP, null);
		sigAndRefsTimestamps = createTimestamps(id_aa_ets_escTimeStamp, VALIDATION_DATA_TIMESTAMP, null);
		archiveTimestamps = createTimestamps(id_aa_ets_archiveTimestampV2, ARCHIVE_TIMESTAMP, CAdES_V2);
		archiveTimestamps.addAll(createTimestamps(id_aa_ets_archiveTimestampV3, ARCHIVE_TIMESTAMP, CAdES_v3));
		final List<TimestampToken> timestampTokenList = getTimestampTokenList();

		final List<String> timestampedTimestamps = new ArrayList<String>();
		for (final TimestampToken timestampToken : timestampTokenList) {

			final TimestampType timestampType = timestampToken.getTimeStampType();
			switch (timestampType) {
				case CONTENT_TIMESTAMP:
					// Will call getContentTimestampData
					break;
				case SIGNATURE_TIMESTAMP:
					timestampToken.setTimestampedReferences(getSignatureTimestampedReferences());
					break;
				case VALIDATION_DATA_REFSONLY_TIMESTAMP:
					timestampToken.setTimestampedReferences(getTimestampedReferences());
					break;
				case VALIDATION_DATA_TIMESTAMP:
					final List<TimestampReference> validationDataReferences = getSignatureTimestampedReferences();
					validationDataReferences.addAll(getTimestampedReferences());
					timestampToken.setTimestampedReferences(validationDataReferences);
					break;
				case ARCHIVE_TIMESTAMP:
					final List<TimestampReference> archiveReferences = getSignatureTimestampedReferences();
					for (final String timestampId : timestampedTimestamps) {

						final TimestampReference timestampReference = new TimestampReference(timestampId);
						archiveReferences.add(timestampReference);
					}
					archiveReferences.addAll(getTimestampedReferences());
					timestampToken.setTimestampedReferences(archiveReferences);
					break;
				default:
					throw new DSSException("TimeStampType not supported : " + timestampType);
			}
			timestampedTimestamps.add(String.valueOf(timestampToken.getDSSId()));
		}
	}

	private List<TimestampToken> getTimestampTokenList() {

		final List<TimestampToken> timestampTokenList = new ArrayList<TimestampToken>();
		timestampTokenList.addAll(contentTimestamps);
		timestampTokenList.addAll(signatureTimestamps);
		timestampTokenList.addAll(refsOnlyTimestamps);
		timestampTokenList.addAll(sigAndRefsTimestamps);
		timestampTokenList.addAll(archiveTimestamps);
		return timestampTokenList;
	}

	private List<TimestampToken> createTimestamps(final ASN1ObjectIdentifier attrType, final TimestampType timestampType, final ArchiveTimestampType archiveTimestampType) {

		final List<TimestampToken> timestampTokenList = new ArrayList<TimestampToken>();
		final AttributeTable attributes = attrType.equals(id_aa_ets_contentTimestamp) ? signerInformation.getSignedAttributes() : signerInformation.getUnsignedAttributes();
		if (attributes != null) {

			final ASN1EncodableVector allAttributes = attributes.getAll(attrType);
			for (int ii = 0; ii < allAttributes.size(); ii++) {
				final Attribute attribute = (Attribute) allAttributes.get(ii);
				final ASN1Set attrValues = attribute.getAttrValues();
				for (final ASN1Encodable value : attrValues.toArray()) {
					if (value instanceof DEROctetString){
						LOG.warn("Illegal content for timestamp (OID : " + attrType + ") : OCTET STRING is not allowed !");
					} else {
						try {
							byte[] encoded = value.toASN1Primitive().getEncoded();
							final CMSSignedData signedData = new CMSSignedData(encoded);
							final TimeStampToken token = new TimeStampToken(signedData);
							final TimestampToken timestampToken = new TimestampToken(token, timestampType, certPool);

							timestampToken.setArchiveTimestampType(archiveTimestampType);
							timestampTokenList.add(timestampToken);
						} catch (Exception e) {
							throw new DSSException(e);
						}
					}
				}
			}
		}
		return timestampTokenList;
	}

	public List<TimestampReference> getSignatureTimestampedReferences() {

		final List<TimestampReference> references = new ArrayList<TimestampReference>();
		final TimestampReference signatureReference = getSignatureTimestampReference();
		references.add(signatureReference);
		final List<TimestampReference> signingCertificateTimestampReferences = getSigningCertificateTimestampReferences();
		references.addAll(signingCertificateTimestampReferences);
		return references;
	}

	private TimestampReference getSignatureTimestampReference() {

		final TimestampReference signatureReference = new TimestampReference(getId());
		return signatureReference;
	}

	private List<TimestampReference> getSigningCertificateTimestampReferences() {

		if (signingCertificateTimestampReferences == null) {

			signingCertificateTimestampReferences = new ArrayList<TimestampReference>();
			final AttributeTable signedAttributes = getSignedAttributes(signerInformation);
			final Attribute signingCertificateAttributeV1 = signedAttributes.get(id_aa_signingCertificate);
			if (signingCertificateAttributeV1 != null) {

				usedCertificatesDigestAlgorithms.add(DigestAlgorithm.SHA1);
				final ASN1Set attrValues = signingCertificateAttributeV1.getAttrValues();
				for (int ii = 0; ii < attrValues.size(); ii++) {

					final ASN1Encodable asn1Encodable = attrValues.getObjectAt(ii);
					final SigningCertificate signingCertificate = SigningCertificate.getInstance(asn1Encodable);
					final ESSCertID[] essCertIDs = signingCertificate.getCerts();
					for (final ESSCertID essCertID : essCertIDs) {

						final byte[] certHash = essCertID.getCertHash();
						final TimestampReference reference = createCertificateTimestampReference(DigestAlgorithm.SHA1, certHash);
						signingCertificateTimestampReferences.add(reference);
					}
				}
			}
			final Attribute signingCertificateAttributeV2 = signedAttributes.get(id_aa_signingCertificateV2);
			if (signingCertificateAttributeV2 != null) {

				final ASN1Set attrValues = signingCertificateAttributeV2.getAttrValues();
				for (int ii = 0; ii < attrValues.size(); ii++) {

					final ASN1Encodable asn1Encodable = attrValues.getObjectAt(ii);
					final SigningCertificateV2 signingCertificateAttribute = SigningCertificateV2.getInstance(asn1Encodable);
					if (signingCertificateAttribute == null) {
						continue;
					}
					final ESSCertIDv2[] essCertIDv2s = signingCertificateAttribute.getCerts();
					for (final ESSCertIDv2 essCertIDv2 : essCertIDv2s) {

						final String algorithmId = essCertIDv2.getHashAlgorithm().getAlgorithm().getId();
						final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(algorithmId);
						usedCertificatesDigestAlgorithms.add(digestAlgorithm);
						final byte[] certHash = essCertIDv2.getCertHash();
						final TimestampReference reference = createCertificateTimestampReference(digestAlgorithm, certHash);
						signingCertificateTimestampReferences.add(reference);
					}
				}
			}
		}
		return signingCertificateTimestampReferences;
	}

	private TimestampReference createCertificateTimestampReference(final DigestAlgorithm digestAlgorithm, final byte[] certHash) {
		final TimestampReference reference = new TimestampReference(digestAlgorithm.getXmlId(), Base64.encodeBase64String(certHash));
		return reference;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {

		String oid = signerInformation.getEncryptionAlgOID();

		try {
			return EncryptionAlgorithm.forOID(oid);
		} catch (RuntimeException e) {
			// purposely empty
		}

		// fallback to identify via signature algorithm
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(oid);
		return signatureAlgorithm.getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {

		final String digestAlgOID = signerInformation.getDigestAlgOID();
		return DigestAlgorithm.forOID(digestAlgOID);
	}

	@Override
	public SignatureCryptographicVerification checkSignatureIntegrity() {

		if (signatureCryptographicVerification != null) {
			return signatureCryptographicVerification;
		}
		signatureCryptographicVerification = new SignatureCryptographicVerification();
		try {

			final List<CertificateValidity> certificateValidityList = getCertificateValidityList();
			if (certificateValidityList.size() == 0) {

				signatureCryptographicVerification.setErrorMessage("There is no signing certificate within the signature.");
				return signatureCryptographicVerification;
			}
			boolean detachedSignature = isDetachedSignature();
			final SignerInformation signerInformationToCheck;
			if (detachedSignature) {

				if (CollectionUtils.isEmpty(detachedContents)) {

					if (certificateValidityList.size() > 0) {
						candidatesForSigningCertificate.setTheCertificateValidity(certificateValidityList.get(0));
					}
					signatureCryptographicVerification.setErrorMessage("Detached file not found!");
					return signatureCryptographicVerification;
				}
				signerInformationToCheck = recreateSignerInformation();
			} else {
				signerInformationToCheck = signerInformation;
			}
			signatureCryptographicVerification.setReferenceDataFound(true);
			LOG.debug("CHECK SIGNATURE VALIDITY: ");
			if (signingCertificateValidity != null) {
				// for (final CertificateValidity certificateValidity :
				// certificateValidityList) {

				try {

					// In the case where one of the mandatory attributes is
					// missing we set already the candidate for the signing
					// certificate.
					// see: validation.at.nqs.bdc.TestNotQualifiedBDC.test1()
					candidatesForSigningCertificate.setTheCertificateValidity(signingCertificateValidity);

					final JcaSimpleSignerInfoVerifierBuilder verifier = new JcaSimpleSignerInfoVerifierBuilder();
					final CertificateToken certificateToken = signingCertificateValidity.getCertificateToken();
					final PublicKey publicKey = certificateToken.getPublicKey();
					final SignerInformationVerifier signerInformationVerifier = verifier.build(publicKey);
					LOG.debug(" - WITH SIGNING CERTIFICATE: " + certificateToken.getAbbreviation());
					boolean signatureIntact = signerInformationToCheck.verify(signerInformationVerifier);
					signatureCryptographicVerification.setReferenceDataIntact(signatureIntact);
					signatureCryptographicVerification.setSignatureIntact(signatureIntact);

				} catch (RuntimeOperatorException e) {

					// Bob: This is a compatibility issue with Java 7. The
					// implementation of the sun.security.rsa.RSASignature class
					// has changed
					// between version 6 and 7. Bouncy castle does not properly
					// take into account the change. Indeed, an exception is
					// thrown by
					// version 7 that BC does not properly catch resulting by
					// raising an exception
					// org.bouncycastle.operator.RuntimeOperatorException.
					LOG.warn(e.getMessage(), e);
				} catch (CMSSignerDigestMismatchException e) {
					LOG.error(e.getMessage(), e);
					signatureCryptographicVerification.setErrorMessage(e.getMessage());
				} catch (OperatorCreationException e) {
					LOG.error(e.getMessage(), e);
					signatureCryptographicVerification.setErrorMessage(e.getMessage());
				} catch (CMSException e) {
					LOG.error(e.getMessage(), e);
					signatureCryptographicVerification.setErrorMessage(e.getMessage());
				} catch (IllegalArgumentException e) {
					// Bob: Can arrive when for example:
					// java.lang.IllegalArgumentException: Unknown signature
					// type requested: RIPEMD160WITH0.4.0.127.0.7.1.1.4.1.6
					// at
					// org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder.generate(Unknown
					// Source)
					// ~[bcpkix-jdk15on-1.49.jar:1.49.0]
					LOG.error(e.getMessage(), e);
					signatureCryptographicVerification.setErrorMessage(e.getMessage());
				}
			}
		} catch (CMSException e) {
			LOG.error(e.getMessage(), e);
			signatureCryptographicVerification.setErrorMessage(e.getMessage());
		} catch (IOException e) {
			LOG.error(e.getMessage(), e);
			signatureCryptographicVerification.setErrorMessage(e.getMessage());
		}
		LOG.debug(" - RESULT: " + signatureCryptographicVerification.toString());
		return signatureCryptographicVerification;
	}

	/**
	 * This method recreates a {@code SignerInformation} with the content using
	 * a {@code CMSSignedDataParser}.
	 *
	 * @return
	 * @throws CMSException
	 * @throws IOException
	 */
	private SignerInformation recreateSignerInformation() throws CMSException, IOException {

		final DSSDocument dssDocument = detachedContents.get(0); // only one
		// element
		// for CAdES
		// Signature
		final InputStream inputStream = dssDocument.openStream();
		final CMSTypedStream signedContent = new CMSTypedStream(inputStream);
		final CMSSignedDataParser cmsSignedDataParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), signedContent, cmsSignedData.getEncoded());
		cmsSignedDataParser.getSignedContent().drain(); // Closes the stream
		final SignerId signerId = signerInformation.getSID();
		final SignerInformation signerInformationToCheck = cmsSignedDataParser.getSignerInfos().get(signerId);
		return signerInformationToCheck;
	}

	private boolean isDetachedSignature() {
		return (cmsSignedData.getSignedContent() == null) || (cmsSignedData.getSignedContent().getContent() == null) ? true : false;
	}

	private List<CertificateValidity> getCertificateValidityList() {

		final List<CertificateValidity> certificateValidityList;
		if (providedSigningCertificateToken == null) {

			// To determine the signing certificate it is necessary to browse
			// through all candidates found before.
			candidatesForSigningCertificate = getCandidatesForSigningCertificate();
		} else {

			candidatesForSigningCertificate = new CandidatesForSigningCertificate();
			final CertificateValidity certificateValidity = new CertificateValidity(providedSigningCertificateToken);
			candidatesForSigningCertificate.add(certificateValidity);
		}
		certificateValidityList = candidatesForSigningCertificate.getCertificateValidityList();
		return certificateValidityList;
	}

	@Override
	public void checkSigningCertificate() {

		// TODO-Bob (13/07/2014):
	}

	@Override
	public String getContentType() {

		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		if (signedAttributes == null) {
			return null;
		}
		final Attribute contentTypeAttribute = signedAttributes.get(PKCSObjectIdentifiers.pkcs_9_at_contentType);
		if (contentTypeAttribute == null) {
			return null;
		}
		final ASN1ObjectIdentifier asn1Encodable = (ASN1ObjectIdentifier) contentTypeAttribute.getAttrValues().getObjectAt(0);
		final String contentType = asn1Encodable.getId();
		return contentType;
	}

	@Override
	public String getContentIdentifier() {

		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		if (signedAttributes == null) {
			return null;
		}
		final Attribute contentIdentifierAttribute = signedAttributes.get(PKCSObjectIdentifiers.id_aa_contentIdentifier);
		if (contentIdentifierAttribute == null) {
			return null;
		}
		final ASN1Encodable asn1Encodable = contentIdentifierAttribute.getAttrValues().getObjectAt(0);
		final ContentIdentifier contentIdentifier = ContentIdentifier.getInstance(asn1Encodable);
		final String contentIdentifierString = DSSASN1Utils.toString(contentIdentifier.getValue());
		return contentIdentifierString;
	}

	@Override
	public String getContentHints() {

		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		if (signedAttributes == null) {
			return null;
		}
		final Attribute contentHintAttribute = signedAttributes.get(PKCSObjectIdentifiers.id_aa_contentHint);
		if (contentHintAttribute == null) {
			return null;
		}
		final ASN1Encodable asn1Encodable = contentHintAttribute.getAttrValues().getObjectAt(0);
		final ContentHints contentHints = ContentHints.getInstance(asn1Encodable);
		final String contentHintsContentType = contentHints.getContentType().toString();
		final String contentHintsContentDescription = contentHints.getContentDescription().getString();
		final String contentHint = contentHintsContentType + " [" + contentHintsContentDescription + "]";
		return contentHint;
	}

	/**
	 * @return the signerInformation
	 */
	public SignerInformation getSignerInformation() {
		return signerInformation;
	}

	@Override
	public List<AdvancedSignature> getCounterSignatures() {
		final List<AdvancedSignature> countersignatures = new ArrayList<AdvancedSignature>();
		for (final Object signer : signerInformation.getCounterSignatures().getSigners()) {
			final SignerInformation signerInformation = (SignerInformation) signer;
			final CAdESSignature countersignature = new CAdESSignature(cmsSignedData, signerInformation, certPool);
			countersignature.setMasterSignature(this);
			countersignatures.add(countersignature);
		}
		return countersignatures;
	}

	@Override
	public List<CertificateRef> getCertificateRefs() {

		final List<CertificateRef> list = new ArrayList<CertificateRef>();

		final AttributeTable attributes = signerInformation.getUnsignedAttributes();
		if (attributes == null) {
			return list;
		}

		final Attribute attribute = attributes.get(id_aa_ets_certificateRefs);
		if (attribute == null) {
			return list;
		}

		final ASN1Set attrValues = attribute.getAttrValues();
		if (attrValues.size() <= 0) {
			return list;
		}

		final ASN1Encodable attrValue = attrValues.getObjectAt(0);
		final ASN1Sequence completeCertificateRefs = (ASN1Sequence) attrValue;

		for (int i = 0; i < completeCertificateRefs.size(); i++) {

			final OtherCertID otherCertId = OtherCertID.getInstance(completeCertificateRefs.getObjectAt(i));
			final CertificateRef certId = new CertificateRef();
			certId.setDigestAlgorithm(otherCertId.getAlgorithmHash().getAlgorithm().getId());
			certId.setDigestValue(otherCertId.getCertHash());

			final IssuerSerial issuer = otherCertId.getIssuerSerial();
			if (issuer != null) {
				final GeneralNames issuerName = issuer.getIssuer();
				if (issuerName != null) {
					certId.setIssuerName(issuerName.toString());
				}
				final ASN1Integer issuerSerial = issuer.getSerial();
				if (issuerSerial != null) {
					certId.setIssuerSerial(issuerSerial.toString());
				}
			}
			list.add(certId);
		}
		return list;
	}

	@Override
	public List<CRLRef> getCRLRefs() {

		final List<CRLRef> list = new ArrayList<CRLRef>();

		try {
			final AttributeTable attributes = signerInformation.getUnsignedAttributes();
			if (attributes == null) {
				return list;
			}

			final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);

			if (attribute == null) {
				return list;
			}

			final ASN1Set attrValues = attribute.getAttrValues();
			if (attrValues.size() <= 0) {
				return list;
			}

			final ASN1Encodable attrValue = attrValues.getObjectAt(0);
			final ASN1Sequence completeCertificateRefs = (ASN1Sequence) attrValue;
			for (int ii = 0; ii < completeCertificateRefs.size(); ii++) {

				final ASN1Encodable completeCertificateRef = completeCertificateRefs.getObjectAt(ii);
				final CrlOcspRef otherCertId = CrlOcspRef.getInstance(completeCertificateRef);
				final CrlListID otherCertIds = otherCertId.getCrlids();
				if (otherCertIds != null) {

					for (final CrlValidatedID id : otherCertIds.getCrls()) {

						final CRLRef crlRef = new CRLRef(id);
						list.add(crlRef);
					}
				}
			}
		} catch (Exception e) {
			// When error in computing or in format, the algorithm just
			// continues.
			LOG.warn("When error in computing or in format the algorithm just continue...", e);
		}
		return list;
	}

	@Override
	public List<OCSPRef> getOCSPRefs() {

		final List<OCSPRef> list = new ArrayList<OCSPRef>();

		final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		if (unsignedAttributes == null) {
			return list;
		}

		final Attribute attribute = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
		if (attribute == null) {
			return list;
		}
		final ASN1Set attrValues = attribute.getAttrValues();
		if (attrValues.size() <= 0) {
			return list;
		}

		final ASN1Encodable attrValue = attrValues.getObjectAt(0);
		final ASN1Sequence completeRevocationRefs = (ASN1Sequence) attrValue;
		for (int i = 0; i < completeRevocationRefs.size(); i++) {

			final CrlOcspRef otherCertId = CrlOcspRef.getInstance(completeRevocationRefs.getObjectAt(i));
			final OcspListID ocspListID = otherCertId.getOcspids();
			if (ocspListID != null) {
				for (final OcspResponsesID ocspResponsesID : ocspListID.getOcspResponses()) {

					final OtherHash otherHash = ocspResponsesID.getOcspRepHash();
					final OCSPRef ocspRef = new OCSPRef(otherHash, true);
					list.add(ocspRef);
				}
			}
		}
		return list;
	}

	@Override
	public byte[] getSignatureTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) {
		return signerInformation.getSignature();
	}

	@Override
	public byte[] getTimestampX1Data(final TimestampToken timestampToken, String canonicalizationMethod) {

		try {

			final ByteArrayOutputStream data = new ByteArrayOutputStream();
			data.write(signerInformation.getSignature());
			// We don't include the outer SEQUENCE, only the attrType and
			// attrValues as stated by the TS Â§6.3.5, NOTE 2
			final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
			if (unsignedAttributes != null) {

				final Attribute attribute = unsignedAttributes.get(id_aa_signatureTimeStampToken);
				if (attribute != null) {

					data.write(DSSASN1Utils.getDEREncoded(attribute.getAttrType()));
					data.write(DSSASN1Utils.getDEREncoded(attribute.getAttrValues()));
				}
			}
			// Those are common to Type 1 and Type 2
			data.write(getTimestampX2Data(timestampToken, null));
			return data.toByteArray();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public byte[] getTimestampX2Data(final TimestampToken timestampToken, String canonicalizationMethod) {

		final ByteArrayOutputStream data = new ByteArrayOutputStream();
		// Those are common to Type 1 and Type 2
		final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		if (unsignedAttributes != null) {

			final Attribute certAttribute = unsignedAttributes.get(id_aa_ets_certificateRefs);
			try {

				if (certAttribute != null) {

					data.write(DSSASN1Utils.getDEREncoded(certAttribute.getAttrType()));
					data.write(DSSASN1Utils.getDEREncoded(certAttribute.getAttrValues()));
				}
				final Attribute revAttribute = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
				if (revAttribute != null) {

					data.write(DSSASN1Utils.getDEREncoded(revAttribute.getAttrType()));
					data.write(DSSASN1Utils.getDEREncoded(revAttribute.getAttrValues()));
				}
			} catch (IOException e) {
				throw new DSSException(e);
			}
		}
		return data.toByteArray();
	}

	@Override
	public byte[] getArchiveTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) throws DSSException {

		final ArchiveTimestampType archiveTimestampType = timestampToken.getArchiveTimestampType();
		final byte[] archiveTimestampData;
		switch (archiveTimestampType) {
			case CAdES_V2:
				archiveTimestampData = getArchiveTimestampDataV2(timestampToken);
				break;
			case CAdES_v3:
				archiveTimestampData = getArchiveTimestampDataV3(timestampToken);
				break;
			default:
				throw new DSSException("Unsupported ArchiveTimestampType " + archiveTimestampType);
		}
		return archiveTimestampData;
	}

	private byte[] getArchiveTimestampDataV3(final TimestampToken timestampToken) throws DSSException {

		final CadesLevelBaselineLTATimestampExtractor timestampExtractor = new CadesLevelBaselineLTATimestampExtractor(this);
		final Attribute atsHashIndexAttribute = timestampExtractor.getVerifiedAtsHashIndex(signerInformation, timestampToken);

		byte[] originalDocumentBytes = getOriginalDocumentBytes();
		final DigestAlgorithm signedDataDigestAlgorithm = timestampToken.getSignedDataDigestAlgo();
		byte[] archiveTimestampData = timestampExtractor.getArchiveTimestampDataV3(signerInformation, atsHashIndexAttribute, originalDocumentBytes, signedDataDigestAlgorithm);
		return archiveTimestampData;
	}

	private byte[] getOriginalDocumentBytes() throws DSSException {

		final CMSTypedData signedContent = cmsSignedData.getSignedContent();
		if (signedContent != null) {
			return CAdESSignature.getSignedContent(signedContent);
		} else {
			if ((detachedContents != null) && (detachedContents.size() > 0)) {

				return detachedContents.get(0).getBytes();
			}
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}
	}

	/**
	 * @param cmsTypedData
	 *            {@code CMSTypedData} cannot be null
	 * @return the signed content extracted from {@code CMSTypedData}
	 */
	public static byte[] getSignedContent(final CMSTypedData cmsTypedData) {
		try {

			final ByteArrayOutputStream originalDocumentData = new ByteArrayOutputStream();
			cmsTypedData.write(originalDocumentData);
			return originalDocumentData.toByteArray();
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (CMSException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method handles the archive-timestamp-v2
	 * The value of the messageImprint field within TimeStampToken shall be a
	 * hash of the concatenation of: • the encapContentInfo element of the
	 * SignedData sequence; • any external content being protected by the
	 * signature, if the eContent element of the encapContentInfo is omitted; •
	 * the Certificates and crls elements of the SignedData sequence, when
	 * present; and • all data elements in the SignerInfo sequence including all
	 * signed and unsigned attributes.
	 * NOTE 1: An alternative archiveTimestamp attribute, identified by an
	 * object identifier { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
	 * pkcs-9(9) smime(16) id-aa(2) 27, is defined in prior versions of TS 101
	 * 733. The archiveTimestamp attribute, defined in versions of TS 101 733
	 * prior to 1.5.1, is not compatible with the attribute defined in the
	 * present document. The archiveTimestamp attribute, defined in versions
	 * 1.5.1 to 1.6.3 of TS 101 733, is compatible with the present document if
	 * the content is internal to encapContentInfo. Unless the version of TS 101
	 * 733 employed by the signing party is known by all recipients, use of the
	 * archiveTimestamp attribute defined in prior versions of TS 101 733 is
	 * deprecated. NOTE 2: Counter signatures held as countersignature
	 * attributes do not require independent archive time-stamps as they are
	 * protected by the archive time-stamp against the containing SignedData
	 * structure. NOTE 3: Unless DER is used throughout, it is recommended that
	 * the binary encoding of the ASN.1 structures being time-stamped be
	 * preserved when being archived to ensure that the recalculation of the
	 * data hash is consistent. NOTE 4: The hash is calculated over the
	 * concatenated data elements as received /stored including the Type and
	 * Length encoding. NOTE 5: Whilst it is recommended that unsigned
	 * attributes be DER encoded, it cannot generally be so guaranteed except by
	 * prior arrangement.
	 *
	 * @param timestampToken
	 * @return
	 * @throws DSSException
	 */
	private byte[] getArchiveTimestampDataV2(TimestampToken timestampToken) throws DSSException {

		try {

			final ByteArrayOutputStream data = new ByteArrayOutputStream();

			final ContentInfo contentInfo = cmsSignedData.toASN1Structure();
			final SignedData signedData = SignedData.getInstance(contentInfo.getContent());

			ContentInfo content = signedData.getEncapContentInfo();
			if ((content == null) || (content.getContent() == null)) {
				/*
				 * Detached signatures have either no encapContentInfo in
				 * signedData, or it exists but has no eContent
				 */
				if (getOriginalDocumentBytes() != null) {
					data.write(content.toASN1Primitive().getEncoded());
					data.write(getOriginalDocumentBytes());
				} else {
					throw new DSSException("Signature is detached and no original data provided.");
				}
			} else {

				ASN1OctetString octet = (ASN1OctetString) content.getContent();

				ContentInfo info2 = new ContentInfo(PKCSObjectIdentifiers.data, octet);
				final byte[] contentInfoBytes = info2.getEncoded();
				if (LOG.isTraceEnabled()) {
					LOG.trace("Content Info: {}", DSSUtils.toHex(contentInfoBytes));
				}
				data.write(contentInfoBytes);
			}
			final ASN1Set certificates = signedData.getCertificates();
			if (certificates != null) {

				final byte[] certificatesBytes = new DERTaggedObject(false, 0, new DERSequence(certificates.toArray())).getEncoded();
				if (LOG.isTraceEnabled()) {
					LOG.trace("Certificates: {}", DSSUtils.toHex(certificatesBytes));
				}
				data.write(certificatesBytes);
			}
			if (signedData.getCRLs() != null) {

				final byte[] crlBytes = signedData.getCRLs().getEncoded();
				if (LOG.isTraceEnabled()) {
					LOG.trace("CRLs: {}", DSSUtils.toHex(crlBytes));
				}
				data.write(crlBytes);
			}
			final SignerInfo signerInfo = signerInformation.toASN1Structure();
			final ByteArrayOutputStream signerByteArrayOutputStream = new ByteArrayOutputStream();
			final ASN1Set unauthenticatedAttributes = signerInfo.getUnauthenticatedAttributes();
			final ASN1Sequence filteredUnauthenticatedAttributes = filterUnauthenticatedAttributes(unauthenticatedAttributes, timestampToken);
			final ASN1Sequence asn1Object = getSignerInfoEncoded(signerInfo, filteredUnauthenticatedAttributes);
			for (int ii = 0; ii < asn1Object.size(); ii++) {

				final byte[] signerInfoBytes = DSSASN1Utils.getDEREncoded(asn1Object.getObjectAt(ii).toASN1Primitive());
				signerByteArrayOutputStream.write(signerInfoBytes);
			}
			final byte[] signerInfoBytes = signerByteArrayOutputStream.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("SignerInfoBytes: {}", DSSUtils.toHex(signerInfoBytes));
			}
			data.write(signerInfoBytes);

			final byte[] result = data.toByteArray();
			return result;

		} catch (IOException e) {
			throw new DSSException(e);
		} catch (Exception e) {
			// When error in computing or in format the algorithm just
			// continues.
			LOG.warn("When error in computing or in format the algorithm just continue...", e);
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}
	}

	/**
	 * Copied from org.bouncycastle.asn1.cms.SignerInfo#toASN1Object() and
	 * adapted to be able to use the custom unauthenticatedAttributes
	 *
	 * @param signerInfo
	 * @param signerInfo
	 * @param unauthenticatedAttributes
	 * @return
	 */
	private ASN1Sequence getSignerInfoEncoded(final SignerInfo signerInfo, final ASN1Encodable unauthenticatedAttributes) {

		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(signerInfo.getVersion());
		v.add(signerInfo.getSID());
		v.add(signerInfo.getDigestAlgorithm());

		final DERTaggedObject signedAttributes = DSSASN1Utils.getSignedAttributes(signerInformation);
		if (signedAttributes != null) {
			v.add(signedAttributes);
		}

		v.add(signerInfo.getDigestEncryptionAlgorithm());
		v.add(signerInfo.getEncryptedDigest());

		if (unauthenticatedAttributes != null) {
			v.add(new DERTaggedObject(false, 1, unauthenticatedAttributes));
		}

		return new DERSequence(v);
	}

	/**
	 * Remove any archive-timestamp-v2/3 attribute added after the
	 * timestampToken
	 */
	private ASN1Sequence filterUnauthenticatedAttributes(ASN1Set unauthenticatedAttributes, TimestampToken timestampToken) {

		ASN1EncodableVector result = new ASN1EncodableVector();
		for (int ii = 0; ii < unauthenticatedAttributes.size(); ii++) {

			final Attribute attribute = Attribute.getInstance(unauthenticatedAttributes.getObjectAt(ii));
			final ASN1ObjectIdentifier attrType = attribute.getAttrType();
			if (id_aa_ets_archiveTimestampV2.equals(attrType) || id_aa_ets_archiveTimestampV3.equals(attrType)) {
				try {

					TimeStampToken token = new TimeStampToken(new CMSSignedData(DSSASN1Utils.getDEREncoded(attribute.getAttrValues().getObjectAt(0).toASN1Primitive())));
					if (!token.getTimeStampInfo().getGenTime().before(timestampToken.getGenerationTime())) {
						continue;
					}
				} catch (Exception e) {
					throw new DSSException(e);
				}
			}
			result.add(unauthenticatedAttributes.getObjectAt(ii));
		}
		return new DERSequence(result);
	}

	@Override
	public String getId() {

		if (signatureId == null) {

			final CertificateToken certificateToken = getSigningCertificateToken();
			final String dssId = certificateToken == null ? "" : certificateToken.getDSSId().asXmlId();
			// Only used to keep the same signature id between CAdES and PAdES
			// signature!
			final Date signingTime = padesSigningTime != null ? padesSigningTime : getSigningTime();
			signatureId = DSSUtils.getDeterministicId(signingTime, dssId);
		}
		return signatureId;
	}

	@Override
	public List<TimestampReference> getTimestampedReferences() {

		final List<TimestampReference> references = new ArrayList<TimestampReference>();
		final List<CertificateRef> certRefs = getCertificateRefs();
		for (final CertificateRef certificateRef : certRefs) {

			final String digestValue = Base64.encodeBase64String(certificateRef.getDigestValue());
			final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(certificateRef.getDigestAlgorithm());
			usedCertificatesDigestAlgorithms.add(digestAlgorithm);
			final TimestampReference reference = new TimestampReference(digestAlgorithm.name(), digestValue);
			references.add(reference);
		}

		final List<OCSPRef> ocspRefs = getOCSPRefs();
		for (final OCSPRef ocspRef : ocspRefs) {

			final DigestAlgorithm digestAlgorithm = ocspRef.getDigestAlgorithm();
			if (digestAlgorithm == null) { // -444
				continue;
			}
			final String digestValue = Base64.encodeBase64String(ocspRef.getDigestValue());
			TimestampReference reference = new TimestampReference(digestAlgorithm.getName(), digestValue, TimestampReferenceCategory.REVOCATION);
			references.add(reference);
		}

		final List<CRLRef> crlRefs = getCRLRefs();
		for (final CRLRef crlRef : crlRefs) {

			final String digestValue = Base64.encodeBase64String(crlRef.getDigestValue());
			TimestampReference reference = new TimestampReference(crlRef.getDigestAlgorithm().getName(), digestValue, TimestampReferenceCategory.REVOCATION);
			references.add(reference);
		}
		return references;
	}

	@Override
	public Set<DigestAlgorithm> getUsedCertificatesDigestAlgorithms() {

		return usedCertificatesDigestAlgorithms;
	}

	/**
	 * @param signerInformation
	 * @return the existing unsigned attributes or an empty attributes hashtable
	 */
	public static AttributeTable getUnsignedAttributes(final SignerInformation signerInformation) {
		final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		if (unsignedAttributes == null) {
			return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Attribute>());
		} else {
			return unsignedAttributes;
		}
	}

	/**
	 * @param signerInformation
	 * @return the existing signed attributes or an empty attributes {@code Hashtable}
	 */
	public static AttributeTable getSignedAttributes(final SignerInformation signerInformation) {

		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		if (signedAttributes == null) {
			return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Attribute>());
		} else {
			return signedAttributes;
		}
	}

	@Override
	public boolean isDataForSignatureLevelPresent(final SignatureLevel signatureLevel) {
		final AttributeTable unsignedAttributes = getUnsignedAttributes(signerInformation);
		final AttributeTable signedAttributes = getSignedAttributes(signerInformation);
		boolean dataForProfilePresent = true;
		switch (signatureLevel) {
			case CAdES_BASELINE_LTA:
				dataForProfilePresent = unsignedAttributes.get(id_aa_ets_archiveTimestampV3) != null;
				// c &= fct() will process fct() all time ; c = c && fct() will process fct() only if c is true
				dataForProfilePresent = dataForProfilePresent && isDataForSignatureLevelPresent(SignatureLevel.CAdES_BASELINE_LT);
				break;
			case CAdES_101733_A:
				dataForProfilePresent = unsignedAttributes.get(id_aa_ets_archiveTimestampV2) != null;
				dataForProfilePresent = dataForProfilePresent && isDataForSignatureLevelPresent(SignatureLevel.CAdES_BASELINE_LT);
				dataForProfilePresent = dataForProfilePresent && isDataForSignatureLevelPresent(SignatureLevel.CAdES_101733_X);
				break;
			case CAdES_BASELINE_LT:
				List<CertificateToken> encapsulatedCertificates = getCertificateSource().getEncapsulatedCertificates();
				int certificateStoreSize = encapsulatedCertificates.size();
				Store crlStore = cmsSignedData.getCRLs();
				int crlStoreSize = crlStore.getMatches(null).size();
				Store ocspStore = cmsSignedData.getOtherRevocationInfo(id_ri_ocsp_response);
				int ocspStoreSize = ocspStore.getMatches(null).size();
				Store ocspBasicStore = cmsSignedData.getOtherRevocationInfo(id_pkix_ocsp_basic);
				int basicOcspStoreSize = ocspBasicStore.getMatches(null).size();
				int ltInfoSize = certificateStoreSize + crlStoreSize + ocspStoreSize + basicOcspStoreSize;
				dataForProfilePresent = (ltInfoSize > 0);
				dataForProfilePresent = dataForProfilePresent && isDataForSignatureLevelPresent(SignatureLevel.CAdES_BASELINE_T);
				break;
			case CAdES_101733_X:
				dataForProfilePresent = ((unsignedAttributes.get(id_aa_ets_certCRLTimestamp) != null) || (unsignedAttributes.get(id_aa_ets_escTimeStamp) != null));
				dataForProfilePresent = dataForProfilePresent && isDataForSignatureLevelPresent(SignatureLevel.CAdES_101733_C);
				break;
			case CAdES_101733_C:
				dataForProfilePresent = unsignedAttributes.get(id_aa_ets_certificateRefs) != null;
				dataForProfilePresent = dataForProfilePresent && isDataForSignatureLevelPresent(SignatureLevel.CAdES_BASELINE_T);
				break;
			case CAdES_BASELINE_T:
				dataForProfilePresent = unsignedAttributes.get(id_aa_signatureTimeStampToken) != null;
				dataForProfilePresent = dataForProfilePresent && isDataForSignatureLevelPresent(SignatureLevel.CAdES_BASELINE_B);
				break;
			case CAdES_BASELINE_B:
				dataForProfilePresent = ((signedAttributes.get(id_aa_signingCertificate) != null) || (signedAttributes.get(id_aa_signingCertificateV2) != null));
				break;
			case CMS_NOT_ETSI:
				dataForProfilePresent = true;
				break;
			default:
				throw new IllegalArgumentException("Unknown level " + signatureLevel);
		}
		return dataForProfilePresent;
	}

	@Override
	public SignatureLevel[] getSignatureLevels() {
		return new SignatureLevel[] {
				SignatureLevel.CMS_NOT_ETSI, SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T, SignatureLevel.CAdES_101733_C, SignatureLevel.CAdES_101733_X,
				SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.CAdES_101733_A, SignatureLevel.CAdES_BASELINE_LTA
		};
	}
}