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
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTaggedObject;
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
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttCertValidityPeriod;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.OID;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.TokenIdentifier;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.SignerAttributeV2;
import eu.europa.esig.dss.cades.signature.CadesLevelBaselineLTATimestampExtractor;
import eu.europa.esig.dss.utils.Utils;
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
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.TimestampReference;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.TimestampedObjectType;
import eu.europa.esig.dss.x509.ArchiveTimestampType;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
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
	 * This id identifies the signature, it is calculated on the signing time if
	 * present and on the certificate.
	 */
	private String signatureId;

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
		this(cms, DSSASN1Utils.getFirstSignerInformation(cms), certPool);
	}

	public CAdESSignature(final CMSSignedData cms, final CertificatePool certPool, List<DSSDocument> detachedContents) {
		this(cms, certPool);
		setDetachedContents(detachedContents);
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

	@Override
	public SignatureForm getSignatureForm() {
		return SignatureForm.CAdES;
	}

	@Override
	public CAdESCertificateSource getCertificateSource() {
		if (certSource == null) {
			certSource = new CAdESCertificateSource(cmsSignedData, certPool);
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

			final X509CertificateHolder x509CertificateHolder = DSSASN1Utils.getX509CertificateHolder(certificateToken);
			final boolean match = signerId.match(x509CertificateHolder);
			certificateValidity.setSignerIdMatch(match);
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

		final IssuerSerial signingTokenIssuerSerial = DSSASN1Utils.getIssuerSerial(signingCertificateValidity.getCertificateToken());
		final BigInteger signingTokenSerialNumber = signingTokenIssuerSerial.getSerial().getValue();
		final GeneralNames signingTokenIssuerName = signingTokenIssuerSerial.getIssuer();

		final AttributeTable signedAttributes = CMSUtils.getSignedAttributes(signerInformation);
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

	private void verifySigningCertificateV1(final BigInteger signingTokenSerialNumber, final GeneralNames signingTokenIssuerName,
			final Attribute signingCertificateAttributeV1) {

		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;
		final byte[] signingTokenCertHash = signingCertificateValidity.getCertificateToken().getDigest(digestAlgorithm);
		if (LOG.isDebugEnabled()) {
			LOG.debug("Candidate Certificate Hash {} with algorithm {}", Utils.toHex(signingTokenCertHash),
					digestAlgorithm);
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
					LOG.debug("Found Certificate Hash in signingCertificateAttributeV1 {} with algorithm {}",
							Utils.toHex(certHash), digestAlgorithm);
				}
				final IssuerSerial issuerSerial = essCertID.getIssuerSerial();
				final boolean match = verifySigningCertificateReferences(signingTokenSerialNumber, signingTokenIssuerName, signingTokenCertHash, certHash,
						issuerSerial);
				if (match) {
					return;
				}
				LOG.warn(
						"RFC 2634: The first certificate identified in the sequence of certificate identifiers MUST be the certificate used to verify the signature.");
			}
		}
	}

	private void verifySigningCertificateV2(final BigInteger signingTokenSerialNumber, final GeneralNames signingTokenIssuerName,
			final Attribute signingCertificateAttributeV2) {

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
					signingTokenCertHash = signingCertificateValidity.getCertificateToken().getDigest(digestAlgorithm);
					if (LOG.isDebugEnabled()) {
						LOG.debug("Candidate Certificate Hash {} with algorithm {}", Utils.toHex(signingTokenCertHash),
								digestAlgorithm);
					}
					lastDigestAlgorithm = digestAlgorithm;
				}
				final byte[] certHash = essCertIDv2.getCertHash();
				signingCertificateValidity.setDigestPresent(true);
				if (LOG.isDebugEnabled()) {
					LOG.debug("Found Certificate Hash in SigningCertificateV2 {} with algorithm {}",
							Utils.toHex(certHash), digestAlgorithm);
				}
				final IssuerSerial issuerSerial = essCertIDv2.getIssuerSerial();
				final boolean match = verifySigningCertificateReferences(signingTokenSerialNumber, signingTokenIssuerName, signingTokenCertHash, certHash,
						issuerSerial);
				if (match) {
					return;
				}
				LOG.warn(
						"RFC 5035: The first certificate identified in the sequence of certificate identifiers MUST be the certificate used to verify the signature.");
			}
		}
	}

	private boolean verifySigningCertificateReferences(final BigInteger signingTokenSerialNumber, final GeneralNames signingTokenIssuerName,
			final byte[] signingTokenCertHash, final byte[] certHash, final IssuerSerial issuerSerial) {

		signingCertificateValidity.setDigest(Utils.toBase64(signingTokenCertHash));
		final boolean hashEqual = Arrays.equals(certHash, signingTokenCertHash);
		signingCertificateValidity.setDigestEqual(hashEqual);

		if (issuerSerial != null) {
			final BigInteger serialNumber = issuerSerial.getSerial().getValue();
			boolean serialNumberEqual = serialNumber.equals(signingTokenSerialNumber);
			signingCertificateValidity.setSerialNumberEqual(serialNumberEqual);

			final GeneralNames issuerName = issuerSerial.getIssuer();

			final String canonicalizedIssuerName = DSSASN1Utils.getCanonicalizedName(issuerName);
			final String canonicalizedSigningTokenIssuerName = DSSASN1Utils.getCanonicalizedName(signingTokenIssuerName);

			// DOES NOT WORK IN ALL CASES:
			// issuerNameEqual = issuerName.equals(signingTokenIssuerName);
			boolean issuerNameEqual = canonicalizedIssuerName.equals(canonicalizedSigningTokenIssuerName);
			signingCertificateValidity.setDistinguishedNameEqual(issuerNameEqual);
		}
		// Validation of the hash is sufficient
		return hashEqual;
	}

	@Override
	public void checkSignaturePolicy(SignaturePolicyProvider signaturePolicyProvider) {
		final Attribute attribute = getSignedAttribute(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
		if (attribute == null) {
			return;
		}

		final ASN1Encodable attrValue = attribute.getAttrValues().getObjectAt(0);
		if (attrValue instanceof DERNull) {
			return;
		}

		final SignaturePolicyId sigPolicy = SignaturePolicyId.getInstance(attrValue);
		if (sigPolicy == null) {
			return;
		}

		final String policyId = sigPolicy.getSigPolicyId().getId();

		signaturePolicy = new SignaturePolicy(policyId);

		final OtherHashAlgAndValue hashAlgAndValue = sigPolicy.getSigPolicyHash();

		final AlgorithmIdentifier digestAlgorithmIdentifier = hashAlgAndValue.getHashAlgorithm();
		final String digestAlgorithmOID = digestAlgorithmIdentifier.getAlgorithm().getId();
		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(digestAlgorithmOID);
		signaturePolicy.setDigestAlgorithm(digestAlgorithm);

		final ASN1OctetString digestValue = hashAlgAndValue.getHashValue();
		final byte[] digestValueBytes = digestValue.getOctets();
		signaturePolicy.setDigestValue(Utils.toBase64(digestValueBytes));

		final SigPolicyQualifiers sigPolicyQualifiers = sigPolicy.getSigPolicyQualifiers();
		if (sigPolicyQualifiers == null) {
			signaturePolicy.setPolicyContent(signaturePolicyProvider.getSignaturePolicyById(policyId));
		} else {
			for (int ii = 0; ii < sigPolicyQualifiers.size(); ii++) {
				try {
					final SigPolicyQualifierInfo policyQualifierInfo = sigPolicyQualifiers.getInfoAt(ii);
					final ASN1ObjectIdentifier policyQualifierInfoId = policyQualifierInfo.getSigPolicyQualifierId();
					final String policyQualifierInfoValue = policyQualifierInfo.getSigQualifier().toString();

					if (PKCSObjectIdentifiers.id_spq_ets_unotice.equals(policyQualifierInfoId)) {
						signaturePolicy.setNotice(policyQualifierInfoValue);
					} else if (PKCSObjectIdentifiers.id_spq_ets_uri.equals(policyQualifierInfoId)) {
						signaturePolicy.setUrl(policyQualifierInfoValue);
						signaturePolicy.setPolicyContent(signaturePolicyProvider.getSignaturePolicyByUrl(policyQualifierInfoValue));
					} else {
						LOG.error("Unknown signature policy qualifier id: {} with value: {}", policyQualifierInfoId,
								policyQualifierInfoValue);
					}
				} catch (Exception e) {
					LOG.error("Unable to read SigPolicyQualifierInfo " + ii, e.getMessage());
				}
			}
			if (signaturePolicy.getPolicyContent() != null) {
				// Updates the OID based cached values
				signaturePolicyProvider.getSignaturePoliciesById().put(policyId, signaturePolicy.getPolicyContent());
			}
		}
	}

	@Override
	public Date getSigningTime() {
		final Attribute attr = getSignedAttribute(PKCSObjectIdentifiers.pkcs_9_at_signingTime);
		if (attr == null) {
			return null;
		}
		final ASN1Set attrValues = attr.getAttrValues();
		final ASN1Encodable attrValue = attrValues.getObjectAt(0);
		final Date signingDate = DSSASN1Utils.getDate(attrValue);
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
							signingDate, attrValue.getClass());
					return null;
				}
			}
			return signingDate;
		}
		if (LOG.isErrorEnabled()) {
			LOG.error("Error when reading signing time. Unrecognized {}", attrValue.getClass());
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
		Attribute signatureProductionPlaceAttr = getSignedAttribute(PKCSObjectIdentifiers.id_aa_ets_signerLocation);
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
		final DirectoryString countryName = signerLocation.getCountry();
		if (countryName != null) {
			signatureProductionPlace.setCountryName(countryName.getString());
		}
		final DirectoryString localityName = signerLocation.getLocality();
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
		signatureProductionPlace.setStreetAddress(address.toString());
		// This property is not used in CAdES version of signature
		// signatureProductionPlace.setStateOrProvince(stateOrProvince);
		return signatureProductionPlace;
	}

	@Override
	public CommitmentType getCommitmentTypeIndication() {
		final Attribute commitmentTypeIndicationAttribute = getSignedAttribute(PKCSObjectIdentifiers.id_aa_ets_commitmentType);
		if (commitmentTypeIndicationAttribute == null) {
			return null;
		}

		try {
			CommitmentType commitmentType = null;
			final ASN1Set attrValues = commitmentTypeIndicationAttribute.getAttrValues();
			final int size = attrValues.size();
			if (size > 0) {
				commitmentType = new CommitmentType();
				for (int ii = 0; ii < size; ii++) {
					if (attrValues.getObjectAt(ii) instanceof DERSequence) {
						final DERSequence derSequence = (DERSequence) attrValues.getObjectAt(ii);
						final CommitmentTypeIndication commitmentTypeIndication = CommitmentTypeIndication.getInstance(derSequence);
						final ASN1ObjectIdentifier commitmentTypeId = commitmentTypeIndication.getCommitmentTypeId();
						commitmentType.addIdentifier(commitmentTypeId.getId());
					} else {
						LOG.warn("Unsupported type for CommitmentType : {}", attrValues.getObjectAt(ii).getClass());
					}
				}
			}
			return commitmentType;
		} catch (Exception e) {
			throw new DSSException("Error when dealing with CommitmentTypeIndication!", e);
		}
	}

	@Override
	public String[] getClaimedSignerRoles() {
		final SignerAttribute signerAttr = getSignerAttributeV1();
		final SignerAttributeV2 signerAttrV2 = getSignerAttributeV2();

		Object[] signerAttrValues = null;
		try {

			if (signerAttr != null) {
				signerAttrValues = signerAttr.getValues();
			} else if (signerAttrV2 != null) {
				signerAttrValues = signerAttrV2.getValues();
			}
			if (signerAttrValues == null) {
				return null;
			}

			final List<String> claimedRoles = new ArrayList<String>();
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
			LOG.error("Error when dealing with claimed signer roles: [" + signerAttrValues + "]", e);
			return null;
		}
	}

	@Override
	public List<CertifiedRole> getCertifiedSignerRoles() {
		final SignerAttribute signerAttr = getSignerAttributeV1();
		final SignerAttributeV2 signerAttrV2 = getSignerAttributeV2();

		Object[] signerAttrValues = null;
		try {
			if (signerAttr != null) {
				signerAttrValues = signerAttr.getValues();
			} else if (signerAttrV2 != null) {
				signerAttrValues = signerAttrV2.getValues();
			}
			if (signerAttrValues == null) {
				return null;
			}
			List<CertifiedRole> roles = null;
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
			LOG.error("Error when dealing with certified signer roles: [" + signerAttrValues + "]", e);
			return null;
		}
	}

	private SignerAttribute getSignerAttributeV1() {
		final Attribute id_aa_ets_signerAttr = getSignedAttribute(PKCSObjectIdentifiers.id_aa_ets_signerAttr);
		if (id_aa_ets_signerAttr != null) {
			final ASN1Set attrValues = id_aa_ets_signerAttr.getAttrValues();
			final ASN1Encodable attrValue = attrValues.getObjectAt(0);
			try {
				return SignerAttribute.getInstance(attrValue);
			} catch (Exception e) {
				LOG.warn("Unable to parse signerAttr " + Utils.toBase64(DSSASN1Utils.getDEREncoded(attrValue)) + "", e);
			}
		}
		return null;
	}

	private SignerAttributeV2 getSignerAttributeV2() {
		final Attribute id_aa_ets_signerAttrV2 = getSignedAttribute(OID.id_aa_ets_signerAttrV2);
		if (id_aa_ets_signerAttrV2 != null) {
			final ASN1Set attrValues = id_aa_ets_signerAttrV2.getAttrValues();
			final ASN1Encodable attrValue = attrValues.getObjectAt(0);
			try {
				return SignerAttributeV2.getInstance(attrValue);
			} catch (Exception e) {
				LOG.warn("Unable to parse signerAttrV2 " + Utils.toBase64(DSSASN1Utils.getDEREncoded(attrValue)) + "", e);
			}
		}
		return null;
	}

	@Override
	public byte[] getContentTimestampData(final TimestampToken timestampToken) {
		return DSSUtils.toByteArray(getOriginalDocument());
	}

	@Override
	public List<TimestampToken> getContentTimestamps() {

		if (contentTimestamps == null) {
			makeTimestampTokens();
		}
		return contentTimestamps;
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() {

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

		final List<TimestampToken> timestampedTimestamps = new ArrayList<TimestampToken>();
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
				timestampToken.setTimestampedReferences(getTimestampReferencesForArchiveTimestamp(timestampedTimestamps));
				break;
			default:
				throw new DSSException("TimeStampType not supported : " + timestampType);
			}
			timestampedTimestamps.add(timestampToken);
		}
	}

	public List<TimestampReference> getTimestampReferencesForArchiveTimestamp(final List<TimestampToken> timestampedTimestamps) {
		final List<TimestampReference> archiveReferences = getSignatureTimestampedReferences();
		for (final TimestampToken timestamp : timestampedTimestamps) {
			archiveReferences.add(new TimestampReference(timestamp.getDSSIdAsString(), TimestampedObjectType.TIMESTAMP));
		}
		archiveReferences.addAll(getTimestampedReferences());
		return archiveReferences;
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

	private List<TimestampToken> createTimestamps(final ASN1ObjectIdentifier attrType, final TimestampType timestampType,
			final ArchiveTimestampType archiveTimestampType) {

		final List<TimestampToken> timestampTokenList = new ArrayList<TimestampToken>();
		final AttributeTable attributes = attrType.equals(id_aa_ets_contentTimestamp) ? signerInformation.getSignedAttributes()
				: signerInformation.getUnsignedAttributes();
		if (attributes != null) {

			final ASN1EncodableVector allAttributes = attributes.getAll(attrType);
			for (int ii = 0; ii < allAttributes.size(); ii++) {
				final Attribute attribute = (Attribute) allAttributes.get(ii);
				final ASN1Set attrValues = attribute.getAttrValues();
				for (final ASN1Encodable value : attrValues.toArray()) {
					if (value instanceof DEROctetString) {
						LOG.warn("Illegal content for timestamp (OID : {}) : OCTET STRING is not allowed !", attrType);
					} else {
						try {
							byte[] encoded = value.toASN1Primitive().getEncoded();
							final TimestampToken timestampToken = new TimestampToken(encoded, timestampType, certPool);

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

	public List<TimestampReference> getSigningCertificateTimestampReferences() {

		if (signingCertificateTimestampReferences == null) {

			signingCertificateTimestampReferences = new ArrayList<TimestampReference>();
			final AttributeTable signedAttributes = CMSUtils.getSignedAttributes(signerInformation);
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
		final TimestampReference reference = new TimestampReference(digestAlgorithm, Utils.toBase64(certHash));
		return reference;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {

		String oid = signerInformation.getEncryptionAlgOID();
		try {
			return EncryptionAlgorithm.forOID(oid);
		} catch (DSSException e) {
			// purposely empty
		}

		// fallback to identify via signature algorithm
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(oid);
		return signatureAlgorithm.getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		final String digestAlgOID = signerInformation.getDigestAlgOID();
		try {
			return DigestAlgorithm.forOID(digestAlgOID);
		} catch (Exception e) {
			LOG.error("Unable to retrieve digest algorithm : " + e.getMessage());
		}
		return null;
	}

	@Override
	public SignatureAlgorithm getSignatureAlgorithm() {
		return SignatureAlgorithm.getAlgorithm(getEncryptionAlgorithm(), getDigestAlgorithm(), getMaskGenerationFunction());
	}

	@Override
	public MaskGenerationFunction getMaskGenerationFunction() {
		try {
			byte[] encryptionAlgParams = signerInformation.getEncryptionAlgParams();
			if (Utils.isArrayNotEmpty(encryptionAlgParams) && !Arrays.equals(DERNull.INSTANCE.getEncoded(), encryptionAlgParams)) {
				RSASSAPSSparams param = RSASSAPSSparams.getInstance(encryptionAlgParams);
				AlgorithmIdentifier maskGenAlgorithm = param.getMaskGenAlgorithm();
				if (PKCSObjectIdentifiers.id_mgf1.equals(maskGenAlgorithm.getAlgorithm())) {
					return MaskGenerationFunction.MGF1;
				} else {
					LOG.warn("Unsupported mask algorithm : {}", maskGenAlgorithm.getAlgorithm());
				}
			}
		} catch (IOException e) {
			LOG.warn("Unable to analyze EncryptionAlgParams", e);
		}
		return null;
	}

	@Override
	public void checkSignatureIntegrity() {
		if (signatureCryptographicVerification != null) {
			return;
		}
		signatureCryptographicVerification = new SignatureCryptographicVerification();
		try {

			final CertificateValidity bestCandidate = getTheBestCandidate();
			if (bestCandidate == null) {
				signatureCryptographicVerification.setErrorMessage("There is no signing certificate within the signature.");
				return;
			}
			boolean detachedSignature = isDetachedSignature();
			final SignerInformation signerInformationToCheck;
			if (detachedSignature) {
				if (Utils.isCollectionEmpty(detachedContents)) {
					candidatesForSigningCertificate.setTheCertificateValidity(bestCandidate);
					signatureCryptographicVerification.setErrorMessage("Detached file not found!");
					return;
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

				} catch (Exception e) {
					LOG.error("Unable to validate CMS Signature : " + e.getMessage(), e);
					signatureCryptographicVerification.setErrorMessage(e.getMessage());
					signatureCryptographicVerification.setReferenceDataIntact(false);
					signatureCryptographicVerification.setSignatureIntact(false);
				}
			}
		} catch (CMSException | IOException e) {
			LOG.error(e.getMessage(), e);
			signatureCryptographicVerification.setErrorMessage(e.getMessage());
		}
		LOG.debug(" - RESULT: {}", signatureCryptographicVerification);
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

		final DSSDocument dssDocument = detachedContents.get(0); // only one element for CAdES Signature
		CMSSignedDataParser cmsSignedDataParser = null;
		if (dssDocument instanceof DigestDocument) {
			cmsSignedDataParser = new CMSSignedDataParser(new PrecomputedDigestCalculatorProvider((DigestDocument) dssDocument), cmsSignedData.getEncoded());
		} else {
			try (InputStream inputStream = dssDocument.openStream()) {
				final CMSTypedStream signedContent = new CMSTypedStream(inputStream);
				cmsSignedDataParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), signedContent, cmsSignedData.getEncoded());
				cmsSignedDataParser.getSignedContent().drain(); // Closes the stream
			}
		}

		final SignerId signerId = signerInformation.getSID();
		final SignerInformation signerInformationToCheck = cmsSignedDataParser.getSignerInfos().get(signerId);
		return signerInformationToCheck;
	}

	private boolean isDetachedSignature() {
		return cmsSignedData.isDetachedSignature();
	}

	private CertificateValidity getTheBestCandidate() {
		if (providedSigningCertificateToken == null) {
			// To determine the signing certificate it is necessary to browse
			// through all candidates found before.
			candidatesForSigningCertificate = getCandidatesForSigningCertificate();
		} else {

			candidatesForSigningCertificate = new CandidatesForSigningCertificate();
			final CertificateValidity certificateValidity = new CertificateValidity(providedSigningCertificateToken);
			candidatesForSigningCertificate.add(certificateValidity);
		}
		return candidatesForSigningCertificate.getTheBestCandidate();
	}

	@Override
	public void checkSigningCertificate() {

		// TODO-Bob (13/07/2014):
	}

	@Override
	public String getContentType() {
		final Attribute contentTypeAttribute = getSignedAttribute(PKCSObjectIdentifiers.pkcs_9_at_contentType);
		if (contentTypeAttribute == null) {
			return null;
		}
		final ASN1ObjectIdentifier asn1Encodable = (ASN1ObjectIdentifier) contentTypeAttribute.getAttrValues().getObjectAt(0);
		final String contentType = asn1Encodable.getId();
		return contentType;
	}

	@Override
	public String getContentIdentifier() {
		final Attribute contentIdentifierAttribute = getSignedAttribute(PKCSObjectIdentifiers.id_aa_contentIdentifier);
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
		final Attribute contentHintAttribute = getSignedAttribute(PKCSObjectIdentifiers.id_aa_contentHint);
		if (contentHintAttribute == null) {
			return null;
		}
		final ASN1Encodable asn1Encodable = contentHintAttribute.getAttrValues().getObjectAt(0);
		final ContentHints contentHints = ContentHints.getInstance(asn1Encodable);
		String contentHint = null;
		if (contentHints != null) {
			// content-type is mandatory
			contentHint = contentHints.getContentType().toString();
			// content-description is optional
			if (contentHints.getContentDescription() != null) {
				contentHint += " [" + contentHints.getContentDescription().toString() + "]";
			}
		}
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

		final Attribute attribute = getUnsignedAttribute(id_aa_ets_certificateRefs);
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
			certId.setDigestAlgorithm(DigestAlgorithm.forOID(otherCertId.getAlgorithmHash().getAlgorithm().getId()));
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
			final Attribute attribute = getUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
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

		final Attribute attribute = getUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
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
		try (ByteArrayOutputStream data = new ByteArrayOutputStream()) {
			data.write(signerInformation.getSignature());
			// We don't include the outer SEQUENCE, only the attrType and
			// attrValues as stated by the TS Â§6.3.5, NOTE 2

			final Attribute attribute = getUnsignedAttribute(id_aa_signatureTimeStampToken);
			if (attribute != null) {
				data.write(DSSASN1Utils.getDEREncoded(attribute.getAttrType()));
				data.write(DSSASN1Utils.getDEREncoded(attribute.getAttrValues()));
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
		try (ByteArrayOutputStream data = new ByteArrayOutputStream()) {
			// Those are common to Type 1 and Type 2
			final Attribute certAttribute = getUnsignedAttribute(id_aa_ets_certificateRefs);
			final Attribute revAttribute = getUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
			if (certAttribute != null) {
				data.write(DSSASN1Utils.getDEREncoded(certAttribute.getAttrType()));
				data.write(DSSASN1Utils.getDEREncoded(certAttribute.getAttrValues()));
			}
			if (revAttribute != null) {
				data.write(DSSASN1Utils.getDEREncoded(revAttribute.getAttrType()));
				data.write(DSSASN1Utils.getDEREncoded(revAttribute.getAttrValues()));
			}

			return data.toByteArray();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public byte[] getArchiveTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) throws DSSException {

		final ArchiveTimestampType archiveTimestampType = timestampToken.getArchiveTimestampType();
		byte[] archiveTimestampData;
		switch (archiveTimestampType) {
		case CAdES_V2:
			/**
			 * There is a difference between message imprint calculation in ETSI TS 101 733 version 1.8.3 and version 2.2.1.
			 * So we first check the message imprint according to 2.2.1 version and then if it fails get the message imprint
			 * data for the 1.8.3 version message imprint calculation. 
			 */
			archiveTimestampData = getArchiveTimestampDataV2(timestampToken);
			if (!timestampToken.matchData(archiveTimestampData, true)) {
				archiveTimestampData = getArchiveTimestampDataV2(timestampToken, false);
			}
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

		final DigestAlgorithm signedDataDigestAlgorithm = timestampToken.getSignedDataDigestAlgo();
		byte[] originalDocumentDigest = DSSUtils.digest(signedDataDigestAlgorithm, getOriginalDocument());
		byte[] archiveTimestampData = timestampExtractor.getArchiveTimestampDataV3(signerInformation, atsHashIndexAttribute, originalDocumentDigest);
		return archiveTimestampData;
	}

	public DSSDocument getOriginalDocument() throws DSSException {
		final CMSTypedData signedContent = cmsSignedData.getSignedContent();
		if (signedContent != null) {
			return new InMemoryDocument(CMSUtils.getSignedContent(signedContent));
		} else if (Utils.collectionSize(detachedContents) == 1) {
			return detachedContents.get(0);
		} else {
			throw new DSSException("Only enveloping and detached signatures are supported");
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
		return getArchiveTimestampDataV2(timestampToken, true);
	}
	
	/**
	 * There is a difference in ETSI TS 101 733 version 1.8.3 and version 2.2.1 in archive-timestamp-v2 hash calculation.
	 * In the 1.8.3 version the calculation did not include the tag and the length octets of the unsigned attributes set.
	 * The hash calculation is described in Annex K in both versions of ETSI TS 101 733.
	 * The differences are in TableK.3: Signed Data in rows 22 and 23.
	 * However, there is a note in 2.2.1 version (Annex K, Table K.3: SignedData, Note 3) that says:
	 * "A previous version of CAdES did not include the tag and length octets of this SET OF type
	 * of unsignedAttrs element in this annex, which contradicted the normative section. To maximize
	 * interoperability, it is recommended to simultaneously compute the two hash values
	 * (including and not including the tag and length octets of SET OF type) and to test
	 * the value of the timestamp against both."
	 * The includeUnsignedAttrsTagAndLength parameter decides whether the tag and length octets are included.
	 * 
	 * According to RFC 5652 it is possible to use DER or BER encoding for SignedData structure.
	 * The exception is the signed attributes attribute and authenticated attributes attributes which
	 * have to be DER encoded. 
	 * 
	 * @param timestampToken
	 * @param includeUnsignedAttrsTagAndLength
	 * @return
	 * @throws DSSException
	 */
	private byte[] getArchiveTimestampDataV2(TimestampToken timestampToken, boolean includeUnsignedAttrsTagAndLength) throws DSSException {

		try (ByteArrayOutputStream data = new ByteArrayOutputStream(); ByteArrayOutputStream signerByteArrayOutputStream = new ByteArrayOutputStream()) {

			final ContentInfo contentInfo = cmsSignedData.toASN1Structure();
			final SignedData signedData = SignedData.getInstance(contentInfo.getContent());
			final ContentInfo content = signedData.getEncapContentInfo();
			byte[] contentInfoBytes;
			if (content.getContent() instanceof BEROctetString) {
				contentInfoBytes = DSSASN1Utils.getBEREncoded(content);
			} else {
				contentInfoBytes = DSSASN1Utils.getDEREncoded(content);
			}
			if (LOG.isTraceEnabled()) {
				LOG.trace("Content Info: {}", DSSUtils.toHex(contentInfoBytes));
			}
			data.write(contentInfoBytes);
			if (isDetachedSignature()) {
				/*
				 * Detached signatures have either no encapContentInfo in signedData, or it
				 * exists but has no eContent
				 */
				byte[] originalDocumentBinaries = DSSUtils.toByteArray(getOriginalDocument());
				if (Utils.isArrayNotEmpty(originalDocumentBinaries)) {
					data.write(originalDocumentBinaries);
				} else {
					throw new DSSException("Signature is detached and no original data provided.");
				}
			}
			
			final ASN1Set certificates = signedData.getCertificates();
			if (certificates != null) {

				byte[] certificatesBytes = null;
				/*
				 * In order to calculate correct message imprint it is important
				 * to use the correct encoding.
				 */
				if (certificates instanceof BERSet) {
					certificatesBytes = new BERTaggedObject(false, 0, new BERSequence(certificates.toArray())).getEncoded();
				} else {
					certificatesBytes = new DERTaggedObject(false, 0, new DERSequence(certificates.toArray())).getEncoded();
				}
				
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
			final ASN1Set unauthenticatedAttributes = signerInfo.getUnauthenticatedAttributes();
			final ASN1Sequence filteredUnauthenticatedAttributes = filterUnauthenticatedAttributes(unauthenticatedAttributes, timestampToken);
			final ASN1Sequence asn1Object = getSignerInfoEncoded(signerInfo, filteredUnauthenticatedAttributes, includeUnsignedAttrsTagAndLength);
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
	 * There is a difference in ETSI TS 101 733 version 1.8.3 and version 2.2.1 in archive-timestamp-v2 hash calculation.
	 * In the 1.8.3 version the calculation did not include the tag and the length octets of the unsigned attributes set.
	 * The hash calculation is described in Annex K in both versions of ETSI TS 101 733.
	 * The differences are in TableK.3: Signed Data in rows 22 and 23.
	 * However, there is a note in 2.2.1 version (Annex K, Table K.3: SignedData, Note 3) that says:
	 * "A previous version of CAdES did not include the tag and length octets of this SET OF type
	 * of unsignedAttrs element in this annex, which contradicted the normative section. To maximize
	 * interoperability, it is recommended to imultaneously compute the two hash values
	 * (including and not including the tag and length octets of SET OF type) and to test
	 * the value of the timestamp against both."
	 * The includeUnsignedAttrsTagAndLength parameter decides whether the tag and length octets are included.
	 *
	 * @param signerInfo
	 * @param signerInfo
	 * @param unauthenticatedAttributes
	 * @param includeUnsignedAttrsTagAndLength
	 * @return
	 */
	private ASN1Sequence getSignerInfoEncoded(final SignerInfo signerInfo, final ASN1Sequence unauthenticatedAttributes, final boolean includeUnsignedAttrsTagAndLength) {

		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(signerInfo.getVersion());
		v.add(signerInfo.getSID());
		v.add(signerInfo.getDigestAlgorithm());

		final DERTaggedObject signedAttributes = CMSUtils.getDERSignedAttributes(signerInformation);
		if (signedAttributes != null) {
			v.add(signedAttributes);
		}

		v.add(signerInfo.getDigestEncryptionAlgorithm());
		v.add(signerInfo.getEncryptedDigest());

		if (unauthenticatedAttributes != null) {
			if (includeUnsignedAttrsTagAndLength) {
				v.add(new DERTaggedObject(false, 1, unauthenticatedAttributes));
			} else {
				for (int i = 0; i < unauthenticatedAttributes.size(); i++) {
					v.add(unauthenticatedAttributes.getObjectAt(i));
				}
			}
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

					TimeStampToken token = new TimeStampToken(
							new CMSSignedData(DSSASN1Utils.getDEREncoded(attribute.getAttrValues().getObjectAt(0).toASN1Primitive())));
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
			final TokenIdentifier identifier = certificateToken == null ? null : certificateToken.getDSSId();
			// Only used to keep the same signature id between CAdES and PAdES
			// signature!
			final Date signingTime = getSigningTime();
			signatureId = DSSUtils.getDeterministicId(signingTime, identifier);
		}
		return signatureId;
	}

	@Override
	public List<TimestampReference> getTimestampedReferences() {

		final List<TimestampReference> references = new ArrayList<TimestampReference>();
		final List<CertificateRef> certRefs = getCertificateRefs();
		for (final CertificateRef certificateRef : certRefs) {

			final String digestValue = Utils.toBase64(certificateRef.getDigestValue());
			final DigestAlgorithm digestAlgorithm = certificateRef.getDigestAlgorithm();
			usedCertificatesDigestAlgorithms.add(digestAlgorithm);
			final TimestampReference reference = new TimestampReference(digestAlgorithm, digestValue);
			references.add(reference);
		}

		addReferencesFromOfflineCRLSource(references);
		addReferencesFromOfflineOCSPSource(references);

		return references;
	}

	private Attribute getSignedAttribute(ASN1ObjectIdentifier oid) {
		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		if (signedAttributes == null) {
			return null;
		}
		return signedAttributes.get(oid);
	}

	private Attribute getUnsignedAttribute(ASN1ObjectIdentifier oid) {
		final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		if (unsignedAttributes == null) {
			return null;
		}
		return unsignedAttributes.get(oid);
	}

	@Override
	public boolean isDataForSignatureLevelPresent(final SignatureLevel signatureLevel) {
		final AttributeTable unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation);
		final AttributeTable signedAttributes = CMSUtils.getSignedAttributes(signerInformation);
		boolean dataForProfilePresent = true;
		switch (signatureLevel) {
		case CAdES_BASELINE_LTA:
			dataForProfilePresent = hasLTAProfile();
			// c &= fct() will process fct() all time ; c = c && fct() will process fct() only if c is true
			dataForProfilePresent = dataForProfilePresent && isDataForSignatureLevelPresent(SignatureLevel.CAdES_BASELINE_LT);
			break;
		case CAdES_101733_A:
			dataForProfilePresent = unsignedAttributes.get(id_aa_ets_archiveTimestampV2) != null;
			dataForProfilePresent = dataForProfilePresent && isDataForSignatureLevelPresent(SignatureLevel.CAdES_BASELINE_LT);
			dataForProfilePresent = dataForProfilePresent && isDataForSignatureLevelPresent(SignatureLevel.CAdES_101733_X);
			break;
		case CAdES_BASELINE_LT:
			dataForProfilePresent = hasLTProfile();
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
			dataForProfilePresent = hasTProfile();
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
		return new SignatureLevel[] { SignatureLevel.CMS_NOT_ETSI, SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T,
				SignatureLevel.CAdES_101733_C, SignatureLevel.CAdES_101733_X, SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.CAdES_101733_A,
				SignatureLevel.CAdES_BASELINE_LTA };
	}

}