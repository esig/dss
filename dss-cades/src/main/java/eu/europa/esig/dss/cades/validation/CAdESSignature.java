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

import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV2;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificate;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificateV2;

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.esf.SigPolicyQualifiers;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ContentIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttCertValidityPeriod;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.SignerAttributeV2;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CAdESCertificateSource;
import eu.europa.esig.dss.validation.CandidatesForSigningCertificate;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.CertificateValidity;
import eu.europa.esig.dss.validation.CommitmentType;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.IssuerSerialInfo;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.SignatureCRLSource;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.SignatureDigestReference;
import eu.europa.esig.dss.validation.SignatureIdentifier;
import eu.europa.esig.dss.validation.SignatureOCSPSource;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.SignerRole;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

/**
 * CAdES Signature class helper
 */
public class CAdESSignature extends DefaultAdvancedSignature {

	private static final long serialVersionUID = 8449504364217200965L;

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignature.class);

	private static final Date JANUARY_1950 = DSSUtils.getUtcDate(1950, 1, 1);

	private static final Date JANUARY_2050 = DSSUtils.getUtcDate(2050, 1, 1);

	private final CMSSignedData cmsSignedData;

	private final SignerInformation signerInformation;

	/**
	 * The reference to the signing certificate. If the signing certificate is
	 * an input provided by the DA then getSigningCer MUST be called.
	 */
	private CertificateValidity signingCertificateValidity;

	/**
	 * @param data
	 *            byte array representing CMSSignedData
	 * @throws org.bouncycastle.cms.CMSException
	 */
	public CAdESSignature(final byte[] data) throws CMSException {
		this(data, new CertificatePool());
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
	public SignatureCertificateSource getCertificateSource() {
		if (offlineCertificateSource == null) {
			offlineCertificateSource = new CAdESCertificateSource(cmsSignedData, signerInformation, certPool);
		}
		return offlineCertificateSource;
	}

	@Override
	public SignatureCRLSource getCRLSource() {
		if (signatureCRLSource == null) {
			try {
				signatureCRLSource = new CAdESCRLSource(cmsSignedData, CMSUtils.getUnsignedAttributes(signerInformation));
			} catch (Exception e) {
				// When error in computing or in format of the algorithm: just
				// continues (will try to get online information)
				LOG.warn("Error in computing or in format of the algorithm: just continue...", e);
			}
		}
		return signatureCRLSource;
	}

	@Override
	public SignatureOCSPSource getOCSPSource() {
		if (signatureOCSPSource == null) {
			signatureOCSPSource = new CAdESOCSPSource(cmsSignedData, CMSUtils.getUnsignedAttributes(signerInformation));
		}
		return signatureOCSPSource;
	}
	
	@Override
	public CAdESTimestampSource getTimestampSource() {
		if (signatureTimestampSource == null) {
			signatureTimestampSource = new CAdESTimestampSource(this, certPool);
		}
		return (CAdESTimestampSource) signatureTimestampSource;
	}
	
	/**
	 * Returns {@code SignerId} of the related to the signature {@code signerInformation}
	 * @return {@link SignerId}
	 */
	public SignerId getSignerId() {
		return signerInformation.getSID();
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
		final SignerId signerId = getSignerId();
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
			LOG.warn("Signing certificate not found: {} {}", signerId.getIssuer(), signerId.getSerialNumber());
		} else if (!verifySignedReferencesToSigningCertificate()) {
			LOG.warn("There is no valid signed reference to the signing certificate: {}", signingCertificateValidity.getCertificateToken().getAbbreviation());
		}
		return candidatesForSigningCertificate;
	}

	private boolean verifySignedReferencesToSigningCertificate() {

		List<CertificateRef> signingCertificateRefs = getCertificateSource().getSigningCertificateValues();
		if (Utils.isCollectionNotEmpty(signingCertificateRefs)) {
			signingCertificateValidity.setAttributePresent(true);

			final CertificateToken foundSigningCertificate = signingCertificateValidity.getCertificateToken();

			for (CertificateRef certificateRef : signingCertificateRefs) {
				Digest certDigest = certificateRef.getCertDigest();
				if (certDigest != null) {
					final byte[] expectedDigest = foundSigningCertificate.getDigest(certDigest.getAlgorithm());
					signingCertificateValidity.setDigestPresent(true);
					signingCertificateValidity.setDigestEqual(Arrays.equals(expectedDigest, certDigest.getValue()));
				}

				IssuerSerialInfo issuerInfo = certificateRef.getIssuerInfo();
				if (issuerInfo != null) {
					signingCertificateValidity.setSerialNumberEqual(foundSigningCertificate.getSerialNumber().equals(issuerInfo.getSerialNumber()));
					signingCertificateValidity
							.setDistinguishedNameEqual(DSSUtils.x500PrincipalAreEquals(foundSigningCertificate.getIssuerX500Principal(), issuerInfo.getIssuerName()));
				}

				// RFC 2634 / 5035 : The first certificate identified in the sequence of
				// certificate identifiers MUST be the certificate used to verify the signature.
				if (signingCertificateValidity.isDigestEqual()) {
					return true;
				}
			}
		}

		return false;
	}

	@Override
	public void checkSignaturePolicy(SignaturePolicyProvider signaturePolicyProvider) {
		final Attribute attribute = getSignedAttribute(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
		if (attribute == null) {
			return;
		}

		final ASN1Encodable attrValue = attribute.getAttrValues().getObjectAt(0);
		if (attrValue instanceof DERNull) {
			signaturePolicy = new SignaturePolicy();
			return;
		}

		final SignaturePolicyId sigPolicy = SignaturePolicyId.getInstance(attrValue);
		if (sigPolicy == null) {
			return;
		}

		final String policyId = sigPolicy.getSigPolicyId().getId();

		signaturePolicy = new SignaturePolicy(policyId);

		final OtherHashAlgAndValue hashAlgAndValue = sigPolicy.getSigPolicyHash();
		final ASN1OctetString digestValue = hashAlgAndValue.getHashValue();
		final byte[] digestValueBytes = digestValue.getOctets();
		boolean zeroHash = isZeroHash(digestValueBytes);
		signaturePolicy.setZeroHash(zeroHash);

		if (!zeroHash) {
			final AlgorithmIdentifier digestAlgorithmIdentifier = hashAlgAndValue.getHashAlgorithm();
			final String digestAlgorithmOID = digestAlgorithmIdentifier.getAlgorithm().getId();
			final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(digestAlgorithmOID);

			signaturePolicy.setDigest(new Digest(digestAlgorithm, digestValueBytes));
		}

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

	private boolean isZeroHash(byte[] hashValue) {
		// The hashValue within the sigPolicyHash may be set to zero to indicate that
		// the policy hash value is not known.
		return (hashValue != null) && (hashValue.length == 1) && (hashValue[0] == 0);
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
	public List<SignerRole> getClaimedSignerRoles() {
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
				return Collections.emptyList();
			}

			final List<SignerRole> claimedRoles = new ArrayList<SignerRole>();
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
							final String role = asn1String.getString();
							claimedRoles.add(new SignerRole(role, EndorsementType.CLAIMED));
						}
					}
				}
			}
			return claimedRoles;
		} catch (Exception e) {
			LOG.error("Error when dealing with claimed signer roles: [" + signerAttrValues + "]", e);
			return Collections.emptyList();
		}
	}

	@Override
	public List<SignerRole> getCertifiedSignerRoles() {
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
				return Collections.emptyList();
			}
			List<SignerRole> roles = new ArrayList<SignerRole>();
			for (final Object signerAttrValue : signerAttrValues) {
				if (signerAttrValue instanceof AttributeCertificate) {
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
						SignerRole certifiedRole = new SignerRole(roleSyntax.getRoleNameAsString(), EndorsementType.CERTIFIED);
						certifiedRole.setNotBefore(DSSASN1Utils.toDate(attrCertValidityPeriod.getNotBeforeTime()));
						certifiedRole.setNotAfter(DSSASN1Utils.toDate(attrCertValidityPeriod.getNotAfterTime()));
						roles.add(certifiedRole);
					}
				}
			}
			return roles;
		} catch (Exception e) {
			LOG.error("Error when dealing with certified signer roles: [" + signerAttrValues + "]", e);
			return Collections.emptyList();
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

	public List<TimestampedReference> getTimestampReferencesForArchiveTimestamp(final List<TimestampToken> timestampedTimestamps) {
		final List<TimestampedReference> archiveReferences = getSignatureTimestampReferences();
		addReferencesForPreviousTimestamps(archiveReferences, timestampedTimestamps);
		addReferences(archiveReferences, getTimestampedReferences());
		return archiveReferences;
	}

	private List<TimestampedReference> getTimestampedReferences() {
		final List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		final List<CertificateToken> certs = getCertificateSource().getCompleteCertificates();
		for (final CertificateToken certificate : certs) {
			references.add(new TimestampedReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
		addReferencesFromRevocationData(references);
		return references;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {

		String oid = signerInformation.getEncryptionAlgOID();
		try {
			return EncryptionAlgorithm.forOID(oid);
		} catch (IllegalArgumentException e) {
			// purposely empty
		}

		// fallback to identify via signature algorithm
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(oid);
		return signatureAlgorithm.getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		final SignatureAlgorithm signatureAlgorithm = getEncryptedDigestAlgo();
		if (signatureAlgorithm != null) {
			if (SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1.equals(signatureAlgorithm)) {
				return getPSSHashAlgorithm();
			}
			return signatureAlgorithm.getDigestAlgorithm();
		} else {
			try {
				final String digestAlgOID = signerInformation.getDigestAlgOID();
				return DigestAlgorithm.forOID(digestAlgOID);
			} catch (IllegalArgumentException e) {
				LOG.warn(e.getMessage());
				return null;
			}
		}
	}

	private SignatureAlgorithm getEncryptedDigestAlgo() {
		try {
			// RFC 3852 states that's a "signature algorithm" (encryption + digest algorithms) and gives as examples :
			// RSA, DSA and ECDSA (encryption algorithm only)
			return SignatureAlgorithm.forOID(signerInformation.getEncryptionAlgOID());
		} catch (RuntimeException e) {
			// purposely empty
			return null;
		}
	}

	public DigestAlgorithm getPSSHashAlgorithm() {
		try {
			byte[] encryptionAlgParams = signerInformation.getEncryptionAlgParams();
			if (Utils.isArrayNotEmpty(encryptionAlgParams) && !Arrays.equals(DERNull.INSTANCE.getEncoded(), encryptionAlgParams)) {
				RSASSAPSSparams param = RSASSAPSSparams.getInstance(encryptionAlgParams);
				AlgorithmIdentifier pssHashAlgo = param.getHashAlgorithm();
				return DigestAlgorithm.forOID(pssHashAlgo.getAlgorithm().getId());
			}
		} catch (IOException e) {
			LOG.warn("Unable to analyze EncryptionAlgParams", e);
		}
		return null;
	}

	@Override
	public MaskGenerationFunction getMaskGenerationFunction() {
		try {
			final SignatureAlgorithm signatureAlgorithm = getEncryptedDigestAlgo();
			if (signatureAlgorithm != null) {
				if (SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1.equals(signatureAlgorithm)) {

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
				}
			}
		} catch (IOException e) {
			LOG.warn("Unable to analyze EncryptionAlgParams", e);
		}
		return null;
	}

	@Override
	public SignatureAlgorithm getSignatureAlgorithm() {
		return SignatureAlgorithm.getAlgorithm(getEncryptionAlgorithm(), getDigestAlgorithm(), getMaskGenerationFunction());
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
			boolean detachedSignature = CMSUtils.isDetachedSignature(cmsSignedData);
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

			LOG.debug("CHECK SIGNATURE VALIDITY: ");
			if (signingCertificateValidity != null) {
				// for (final CertificateValidity certificateValidity :
				// certificateValidityList) {

				try {
					candidatesForSigningCertificate.setTheCertificateValidity(signingCertificateValidity);

					final JcaSimpleSignerInfoVerifierBuilder verifier = new JcaSimpleSignerInfoVerifierBuilder();
					verifier.setProvider(DSSSecurityProvider.getSecurityProviderName());

					final CertificateToken certificateToken = signingCertificateValidity.getCertificateToken();
					final PublicKey publicKey = certificateToken.getPublicKey();
					final SignerInformationVerifier signerInformationVerifier = verifier.build(publicKey);
					LOG.debug(" - WITH SIGNING CERTIFICATE: {}", certificateToken.getAbbreviation());
					boolean signatureIntact = signerInformationToCheck.verify(signerInformationVerifier);
					signatureCryptographicVerification.setSignatureIntact(signatureIntact);

				} catch (CMSSignerDigestMismatchException e) {
					LOG.warn("Unable to validate CMS Signature : {}", e.getMessage());
					signatureCryptographicVerification.setErrorMessage(e.getMessage());
					signatureCryptographicVerification.setSignatureIntact(false);
				} catch (Exception e) {
					LOG.error("Unable to validate CMS Signature : " + e.getMessage(), e);
					signatureCryptographicVerification.setErrorMessage(e.getMessage());
					signatureCryptographicVerification.setSignatureIntact(false);
				}
			}

			boolean referenceDataFound = true;
			boolean referenceDataIntact = true;
			List<ReferenceValidation> refValidations = getReferenceValidations(signerInformationToCheck);
			for (ReferenceValidation referenceValidation : refValidations) {
				referenceDataFound = referenceDataFound && referenceValidation.isFound();
				referenceDataIntact = referenceDataIntact && referenceValidation.isIntact();
			}
			signatureCryptographicVerification.setReferenceDataFound(referenceDataFound);
			signatureCryptographicVerification.setReferenceDataIntact(referenceDataIntact);
			
		} catch (CMSException | IOException e) {
			LOG.error(e.getMessage(), e);
			signatureCryptographicVerification.setErrorMessage(e.getMessage());
		}
		LOG.debug(" - RESULT: {}", signatureCryptographicVerification);
	}
	
	public List<ReferenceValidation> getReferenceValidations(SignerInformation signerInformationToCheck) {
		if (referenceValidations == null) {
			referenceValidations = new ArrayList<ReferenceValidation>();
			ReferenceValidation validation = new ReferenceValidation();
			validation.setType(DigestMatcherType.MESSAGE_DIGEST);

			DSSDocument originalDocument = null;
			try {
				originalDocument = getOriginalDocument();
			} catch (DSSException e) {
				validation.setFound(false);
			}

			Set<DigestAlgorithm> messageDigestAlgorithms = getMessageDigestAlgorithms();
			byte[] expectedMessageDigestValue = getMessageDigestValue();
			
			if (originalDocument != null) {
					
				if (Utils.isArrayNotEmpty(expectedMessageDigestValue)) {
					Digest messageDigest = new Digest();
					messageDigest.setValue(expectedMessageDigestValue);
					
					validation.setFound(true);
					
					if (Utils.isCollectionNotEmpty(messageDigestAlgorithms)) {

						// try to match with found digest algorithm(s)
						for (DigestAlgorithm digestAlgorithm : messageDigestAlgorithms) {
							String base64Digest = originalDocument.getDigest(digestAlgorithm);
							if (Arrays.equals(expectedMessageDigestValue, Utils.fromBase64(base64Digest))) {
								messageDigest.setAlgorithm(digestAlgorithm);
								validation.setIntact(true);
								break;
							}
						}
						
						// add digest algorithm if message digest does not much
						if (messageDigest.getAlgorithm() == null && messageDigestAlgorithms.size() == 1) {
							messageDigest.setAlgorithm(messageDigestAlgorithms.iterator().next());
						}
						validation.setDigest(messageDigest);
						
					} else {
						LOG.warn("Message DigestAlgorithms not found in SignedData! Reference validation is not possible.");
						
					}
					
					// get references to documents contained in the manifest file (for ASiC-E container)
					if (validation.isFound()) {
						validation.getDependentValidations().addAll(getManifestEntryValidation(originalDocument, messageDigest));
					}
					
				} else {
					LOG.warn("message-digest is not present in SignedData!");
					if (signerInformationToCheck != null) {
						LOG.warn("Extracting digests from content SignatureValue...");
						validation = getContentReferenceValidation(originalDocument, signerInformationToCheck);
					}
					
				}
			} else {
				LOG.warn("The original document is not found or cannot be extracted. Reference validation is not possible.");
				
			}
			
			referenceValidations.add(validation);

		}
		return referenceValidations;
	}
	
	private List<ReferenceValidation> getManifestEntryValidation(final DSSDocument originalDocument, final Digest messageDigest) {
		List<ReferenceValidation> manifestEntryValidations = new ArrayList<ReferenceValidation>();
		ManifestFile manifest = getSignedManifest(originalDocument, messageDigest);
		if (manifest == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("No related manifest file found for a signature with name [{}]", getSignatureFilename());
			}
			return manifestEntryValidations;
		}
		for (ManifestEntry entry : manifest.getEntries()) {
			ReferenceValidation entryValidation = new ReferenceValidation();
			entryValidation.setType(DigestMatcherType.MANIFEST_ENTRY);
			entryValidation.setName(entry.getFileName());
			entryValidation.setDigest(entry.getDigest());
			entryValidation.setFound(entry.isFound());
			entryValidation.setIntact(entry.isIntact());
			manifestEntryValidations.add(entryValidation);
		}
		
		return manifestEntryValidations;
	}
	
	private ManifestFile getSignedManifest(final DSSDocument originalDocument, final Digest messageDigest) {
		if (Utils.isCollectionNotEmpty(manifestFiles)) {
			DigestAlgorithm digestAlgorithm = messageDigest.getAlgorithm() != null ? messageDigest.getAlgorithm() : DigestAlgorithm.SHA256;
			String digestValue = originalDocument.getDigest(digestAlgorithm);
			
			for (ManifestFile manifestFile : manifestFiles) {
				if (digestValue.equals(manifestFile.getDigestBase64String(digestAlgorithm))) {
					return manifestFile;
				}
			}
		}
		return null;
	}

	@Override
	public List<ReferenceValidation> getReferenceValidations() {
		return getReferenceValidations(null);
	}
	
	private ReferenceValidation getContentReferenceValidation(DSSDocument originalDocument, SignerInformation signerInformation) {
		ReferenceValidation contentValidation = new ReferenceValidation();
		contentValidation.setType(DigestMatcherType.CONTENT_DIGEST);
		DigestAlgorithm digestAlgorithm = getDigestAlgorithmForOID(signerInformation.getDigestAlgOID());
		if (originalDocument != null && digestAlgorithm != null) {
			byte[] contentDigest = signerInformation.getContentDigest();
			if (Utils.isArrayNotEmpty(contentDigest)) {
				contentValidation.setFound(true);
				contentValidation.setDigest(new Digest(digestAlgorithm, contentDigest));
				if (Arrays.equals(contentDigest, Utils.fromBase64(originalDocument.getDigest(digestAlgorithm)))) {
					contentValidation.setIntact(true);
				}
			}
		}
		return contentValidation;
	}
	
	/**
	 * TS 119 442 - V1.1.1 - Electronic Signatures and Infrastructures (ESI), ch. 5.1.4.2.1.3 XML component:
	 * 
	 * In case of CAdES signatures, the input to the digest value computation shall be one of the DER-encoded
	 * instances of SignedInfo type present within the CMS structure. 
	 */
	@Override
	public SignatureDigestReference getSignatureDigestReference(DigestAlgorithm digestAlgorithm) {
		byte[] derEncodedSignerInfo = DSSASN1Utils.getDEREncoded(signerInformation.toASN1Structure());
		byte[] digestValue = DSSUtils.digest(digestAlgorithm, derEncodedSignerInfo);
		return new SignatureDigestReference(new Digest(digestAlgorithm, digestValue));
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

		final SignerId signerId = getSignerId();
		final SignerInformation signerInformationToCheck = cmsSignedDataParser.getSignerInfos().get(signerId);
		return signerInformationToCheck;
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

	public Set<DigestAlgorithm> getMessageDigestAlgorithms() {
		Set<DigestAlgorithm> result = new HashSet<DigestAlgorithm>();
		Set<AlgorithmIdentifier> digestAlgorithmIDs = cmsSignedData.getDigestAlgorithmIDs();
		for (AlgorithmIdentifier algorithmIdentifier : digestAlgorithmIDs) {
			String oid = algorithmIdentifier.getAlgorithm().getId();
			DigestAlgorithm digestAlgorithm = getDigestAlgorithmForOID(oid);
			if (digestAlgorithm != null) {
				result.add(DigestAlgorithm.forOID(oid));
			}
		}
		return result;
	}
	
	private DigestAlgorithm getDigestAlgorithmForOID(String oid) {
		try {
			return DigestAlgorithm.forOID(oid);
		} catch (IllegalArgumentException e) {
			LOG.warn("Not a digest algorithm {} : {}", oid, e.getMessage());
			return null;
		}
	}

	@Override
	public byte[] getMessageDigestValue() {
		final Attribute messageDigestAttribute = getSignedAttribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest);
		if (messageDigestAttribute == null) {
			return null;
		}
		final ASN1OctetString asn1OctetString = (ASN1OctetString) messageDigestAttribute.getAttrValues().getObjectAt(0);
		return asn1OctetString.getOctets();
	}

	@Override
	public String getContentType() {
		final Attribute contentTypeAttribute = getSignedAttribute(PKCSObjectIdentifiers.pkcs_9_at_contentType);
		if (contentTypeAttribute == null) {
			return null;
		}
		final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) contentTypeAttribute.getAttrValues().getObjectAt(0);
		return oid.getId();
	}

	@Override
	public String getMimeType() {
		final Attribute mimeTypeAttribute = getSignedAttribute(OID.id_aa_ets_mimeType);
		if (mimeTypeAttribute == null) {
			return null;
		}
		return DSSASN1Utils.getString(mimeTypeAttribute.getAttrValues().getObjectAt(0));
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
	public byte[] getSignatureValue() {
		return signerInformation.getSignature();
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
		return getCertificateSource().getCompleteCertificateRefs();
	}

	public DSSDocument getOriginalDocument() throws DSSException {
		return CMSUtils.getOriginalDocument(cmsSignedData, detachedContents);
	}
	
	@Override
	protected SignatureIdentifier buildSignatureIdentifier() {
		final CertificateToken certificateToken = getSigningCertificateToken();
		final TokenIdentifier identifier = certificateToken == null ? null : certificateToken.getDSSId();
		
		// introduce additional variables in order to avoid signatures with duplicate ids
		Integer uniqueInteger = getUniqueIntegerIfNeeded();
		if (uniqueInteger == 0) uniqueInteger = null;
		String masterSignatureId = getMasterSignatureId();
		String fileName = getSignatureFilename();

		return SignatureIdentifier.buildSignatureIdentifier(getSigningTime(), identifier, uniqueInteger, masterSignatureId, fileName);
	}
	
	/**
	 * Returns Id of the {@code masterSignature} if exists, otherwise returns NULL
	 * @return {@link String} masterSignature id
	 */
	private String getMasterSignatureId() {
		AdvancedSignature masterSignature = getMasterSignature();
		if (masterSignature != null) {
			return masterSignature.getId();
		}
		return null;
	}
	
	/**
	 * Returns the related position of {@code this.signerInformation} in the cmsSignedData
	 * among signers with the same SID
	 * @return
	 */
	private int getUniqueIntegerIfNeeded() {
		Collection<SignerInformation> signerInformations;
		if (getMasterSignature() == null) {
			signerInformations = cmsSignedData.getSignerInfos().getSigners(getSignerId());
		} else {
			signerInformations = this.signerInformation.getCounterSignatures().getSigners(getSignerId());
		}
		int counter = 0;
		for (SignerInformation signerInformation : signerInformations) {
			if (this.signerInformation == signerInformation) {
				break;
			}
			counter++;
		}
		return counter;
	}
	
	@Override
	public String getDAIdentifier() {
		// not applicable for CAdES
		return null;
	}

	private Attribute getSignedAttribute(ASN1ObjectIdentifier oid) {
		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		if (signedAttributes == null) {
			return null;
		}
		return signedAttributes.get(oid);
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
