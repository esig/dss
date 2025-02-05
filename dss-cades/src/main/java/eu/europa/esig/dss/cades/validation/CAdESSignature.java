/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.cades.CAdESUtils;
import eu.europa.esig.dss.cades.SignedAssertion;
import eu.europa.esig.dss.cades.SignedAssertions;
import eu.europa.esig.dss.cades.SignerAttributeV2;
import eu.europa.esig.dss.cades.validation.scope.CAdESSignatureScopeFinder;
import eu.europa.esig.dss.cades.validation.timestamp.CAdESTimestampSource;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.signature.CommitmentTypeIndication;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.model.signature.SignatureDigestReference;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.model.signature.SignatureProductionPlace;
import eu.europa.esig.dss.model.signature.SignerRole;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.signature.DefaultAdvancedSignature;
import eu.europa.esig.dss.spi.signature.identifier.SignatureIdentifierBuilder;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import eu.europa.esig.dss.spi.x509.SignerIdentifier;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SPUserNotice;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.esf.SigPolicyQualifiers;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
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
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.NoticeReference;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static eu.europa.esig.dss.spi.OID.id_aa_ets_sigPolicyStore;

/**
 * CAdES Signature class helper
 */
public class CAdESSignature extends DefaultAdvancedSignature {

	private static final long serialVersionUID = 8449504364217200965L;

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignature.class);

	/** The CMS of the signature */
	private final CMS cms;

	/** The corresponding SignerInformation to the signature */
	private final SignerInformation signerInformation;

	/**
	 * NOTE: The value shall be cached in order to properly compute a unique
	 * identifier for counter signatures
	 */
	private SignerInformationStore counterSignaturesStore;

	/**
	 * The default constructor for CAdESSignature.
	 *
	 * @param cms
	 *            CMS
	 * @param signerInformation
	 *            an expanded SignerInfo block from a CMS Signed message
	 */
	public CAdESSignature(final CMS cms, final SignerInformation signerInformation) {
		Objects.requireNonNull(cms, "CMS cannot be null!");
		Objects.requireNonNull(signerInformation, "SignerInformation must be provided!");
		this.cms = cms;
		this.signerInformation = signerInformation;
	}

	@Override
	public SignatureForm getSignatureForm() {
		return SignatureForm.CAdES;
	}

	@Override
	public SignatureCertificateSource getCertificateSource() {
		if (offlineCertificateSource == null) {
			offlineCertificateSource = new CAdESCertificateSource(cms, signerInformation);
		}
		return offlineCertificateSource;
	}

	@Override
	public OfflineCRLSource getCRLSource() {
		if (signatureCRLSource == null) {
			try {
				signatureCRLSource = new CAdESCRLSource(cms, signerInformation.getUnsignedAttributes());
			} catch (Exception e) {
				// When error in computing or in format of the algorithm: just
				// continues (will try to get online information)
				LOG.warn("Error in computing or in format of the algorithm: just continue...", e);
			}
		}
		return signatureCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {
		if (signatureOCSPSource == null) {
			signatureOCSPSource = new CAdESOCSPSource(cms, signerInformation.getUnsignedAttributes());
		}
		return signatureOCSPSource;
	}
	
	@Override
	public CAdESTimestampSource getTimestampSource() {
		if (signatureTimestampSource == null) {
			signatureTimestampSource = new CAdESTimestampSource(this);
		}
		return (CAdESTimestampSource) signatureTimestampSource;
	}
	
	/**
	 * Returns {@code SignerId} of the related to the signature {@code signerInformation}
	 *
	 * @return {@link SignerId}
	 */
	public SignerId getSignerId() {
		return signerInformation.getSID();
	}

	@Override
	protected List<SignatureScope> findSignatureScopes() {
		return new CAdESSignatureScopeFinder().findSignatureScope(this);
	}

	@Override
	protected SignaturePolicy buildSignaturePolicy() {
		final Attribute attribute = CAdESUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
		if (attribute == null) {
			return null;
		}

		final ASN1Encodable attrValue = attribute.getAttrValues().getObjectAt(0);

		SignaturePolicyIdentifier signaturePolicyIdentifier = SignaturePolicyIdentifier.getInstance(attrValue);
		if (signaturePolicyIdentifier.isSignaturePolicyImplied()) {
			signaturePolicy = new SignaturePolicy();
			return signaturePolicy;
		}

		final SignaturePolicyId sigPolicy = signaturePolicyIdentifier.getSignaturePolicyId();
		if (sigPolicy == null) {
			return null;
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
		if (sigPolicyQualifiers != null) {
			for (int ii = 0; ii < sigPolicyQualifiers.size(); ii++) {
				try {
					final SigPolicyQualifierInfo policyQualifierInfo = sigPolicyQualifiers.getInfoAt(ii);
					final ASN1ObjectIdentifier policyQualifierInfoId = policyQualifierInfo.getSigPolicyQualifierId();
					final String policyQualifierInfoValue = policyQualifierInfo.getSigQualifier().toString();

					if (PKCSObjectIdentifiers.id_spq_ets_uri.equals(policyQualifierInfoId)) {
						signaturePolicy.setUri(policyQualifierInfoValue);

					} else if (PKCSObjectIdentifiers.id_spq_ets_unotice.equals(policyQualifierInfoId)) {
						final SPUserNotice spUserNotice = SPUserNotice.getInstance(policyQualifierInfo.getSigQualifier());
						signaturePolicy.setUserNotice(buildSPUserNoticeString(spUserNotice));

					} else if (OID.id_sp_doc_specification.equals(policyQualifierInfoId)) {
						final SpDocSpecification spDocSpecification = new SpDocSpecification();
						spDocSpecification.setId(policyQualifierInfoValue);
						signaturePolicy.setDocSpecification(spDocSpecification);

					} else {
						LOG.warn("Unknown signature policy qualifier id: {} with value: {}", policyQualifierInfoId,
								policyQualifierInfoValue);
					}

				} catch (Exception e) {
					LOG.warn("Unable to read SigPolicyQualifierInfo {} : {}", ii, e.getMessage());
				}
			}
		}
		
		return signaturePolicy;
	}

	private UserNotice buildSPUserNoticeString(SPUserNotice spUserNotice) {
		final UserNotice userNotice = new UserNotice();

		final NoticeReference noticeRef = spUserNotice.getNoticeRef();
		if (noticeRef != null) {
			final DisplayText organization = noticeRef.getOrganization();
			if (organization != null) {
				userNotice.setOrganization(organization.getString());
			}
			final ASN1Integer[] noticeNumbers = noticeRef.getNoticeNumbers();
			if (noticeNumbers != null && noticeNumbers.length != 0) {
				int[] noticeNumbersArray = new int[noticeNumbers.length];
				for (int i = 0; i < noticeNumbers.length ; i++) {
					noticeNumbersArray[i] = noticeNumbers[i].intValueExact();
				}
				userNotice.setNoticeNumbers(noticeNumbersArray);
			}
		}
		final DisplayText explicitText = spUserNotice.getExplicitText();
		if (explicitText != null) {
			userNotice.setExplicitText(explicitText.getString());
		}

		return userNotice;
	}
	
	@Override
	public SignaturePolicyStore getSignaturePolicyStore() {
		final Attribute sigPolicyStore = CAdESUtils.getUnsignedAttribute(signerInformation, id_aa_ets_sigPolicyStore);
		if (sigPolicyStore != null && sigPolicyStore.getAttrValues().size() > 0) {
			SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
			SpDocSpecification spDocSpecification = new SpDocSpecification();
			
			ASN1Sequence sequence = ASN1Sequence.getInstance(sigPolicyStore.getAttrValues().getObjectAt(0));
			
			if (sequence.size() == 2) {
				ASN1Encodable spDocSpec = sequence.getObjectAt(0);
				spDocSpecification.setId(spDocSpec.toString());

				ASN1Encodable spDocument = sequence.getObjectAt(1);
				if (spDocument instanceof ASN1OctetString) {
					ASN1OctetString sigPolicyEncoded = ASN1OctetString.getInstance(spDocument);
					signaturePolicyStore.setSignaturePolicyContent(new InMemoryDocument(sigPolicyEncoded.getOctets()));

				} else if (spDocument instanceof ASN1IA5String) {
					ASN1String sigPolicyLocalURI = ASN1IA5String.getInstance(spDocument);
					signaturePolicyStore.setSigPolDocLocalURI(sigPolicyLocalURI.getString());

				} else {
					LOG.warn("Unable to extract a signature-policy-store spDocument. " +
							"One of 'sigPolicyEncoded' or 'sigPolicyLocalURI' is expected!");
				}
				signaturePolicyStore.setSpDocSpecification(spDocSpecification);
				return signaturePolicyStore;

			} else {
				LOG.warn("Unable to extract a signature-policy-store. The element shall contain two attributes.");
			}
		}
		return null;
	}

	private boolean isZeroHash(byte[] hashValue) {
		// The hashValue within the sigPolicyHash may be set to zero or be empty to indicate that
		// the policy hash value is not known.
		return isZeroHashEmpty(hashValue) || doesZeroHashContainSigneZeroByte(hashValue);
	}
	
	private boolean isZeroHashEmpty(byte[] hashValue) {
		return (hashValue != null) && (hashValue.length == 0);
	}
	
	private boolean doesZeroHashContainSigneZeroByte(byte[] hashValue) {
		return (hashValue != null) && (hashValue.length == 1) && ((hashValue[0] == '0') || (hashValue[0] == 0x00));
	}

	@Override
	public Date getSigningTime() {
		final Attribute attr = CAdESUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.pkcs_9_at_signingTime);
		if (attr == null) {
			return null;
		}
		final ASN1Set attrValues = attr.getAttrValues();
		final ASN1Encodable attrValue = attrValues.getObjectAt(0);
		return CAdESUtils.readSigningDate(attrValue);
	}

	/**
	 * Gets CMS
	 *
	 * @return {@link CMS} the cms
	 */
	public CMS getCMS() {
		return cms;
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {
		Attribute signatureProductionPlaceAttr = CAdESUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_signerLocation);
		if (signatureProductionPlaceAttr == null) {
			return null;
		}

		final ASN1Encodable asn1Encodable = signatureProductionPlaceAttr.getAttrValues().getObjectAt(0);
		SignerLocation signerLocation = null;
		try {
			signerLocation = SignerLocation.getInstance(asn1Encodable);
		} catch (Exception e) {
			String errorMessage = "Unable to build a SignerLocation instance. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, e.getMessage());
			}
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

		final ASN1Sequence seq = signerLocation.getPostalAddress();
		if (seq != null) {
			for (int ii = 0; ii < seq.size(); ii++) {
				String postalAddress = DSSASN1Utils.getDirectoryStringValue(seq.getObjectAt(ii));
				if (Utils.isStringNotEmpty(postalAddress)) {
					signatureProductionPlace.getPostalAddress().add(postalAddress);
				}
			}
		}

		return signatureProductionPlace;
	}

	@Override
	public List<CommitmentTypeIndication> getCommitmentTypeIndications() {
		final Attribute commitmentTypeIndicationAttribute = CAdESUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_commitmentType);
		if (commitmentTypeIndicationAttribute == null) {
			return Collections.emptyList();
		}

		try {
			List<eu.europa.esig.dss.model.signature.CommitmentTypeIndication> commitmentTypeIndications = null;
			final ASN1Set attrValues = commitmentTypeIndicationAttribute.getAttrValues();
			final int size = attrValues.size();
			if (size > 0) {
				commitmentTypeIndications = new ArrayList<>();
				for (int ii = 0; ii < size; ii++) {
					if (attrValues.getObjectAt(ii) instanceof ASN1Sequence) {
						final ASN1Sequence sequence = (ASN1Sequence) attrValues.getObjectAt(ii);
						final org.bouncycastle.asn1.esf.CommitmentTypeIndication commitmentTypeIndication =
								org.bouncycastle.asn1.esf.CommitmentTypeIndication.getInstance(sequence);
						final ASN1ObjectIdentifier commitmentTypeId = commitmentTypeIndication.getCommitmentTypeId();
						commitmentTypeIndications.add(new eu.europa.esig.dss.model.signature.CommitmentTypeIndication(commitmentTypeId.getId()));
					} else {
						LOG.warn("Unsupported type for CommitmentType : {}", attrValues.getObjectAt(ii).getClass());
					}
				}
			}
			return commitmentTypeIndications;
		} catch (Exception e) {
			LOG.warn("An error while extracting CommitmentTypeIndication. Reason : {}", e.getMessage(), e);
			return Collections.emptyList();
		}
	}

	@Override
	public List<SignerRole> getSignedAssertions() {
		List<SignerRole> result = new ArrayList<>();
		final SignerAttributeV2 signerAttrV2 = getSignerAttributeV2();
		if (signerAttrV2 != null) {
		    for (final Object signerAttrValue : signerAttrV2.getValues()) {
			    if (signerAttrValue instanceof SignedAssertions) {
				    List<SignedAssertion> assertions = ((SignedAssertions) signerAttrValue).getAssertions();
				    for (SignedAssertion sa: assertions) {
						result.add(new SignerRole(sa.toString(), EndorsementType.SIGNED));
				    }
			    }
		    }
		}
		return result;
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

			final List<SignerRole> claimedRoles = new ArrayList<>();
			for (final Object signerAttrValue : signerAttrValues) {
				if (!(signerAttrValue instanceof org.bouncycastle.asn1.x509.Attribute[])) {
					continue;
				}
				final org.bouncycastle.asn1.x509.Attribute[] signerAttrValueArray = (org.bouncycastle.asn1.x509.Attribute[]) signerAttrValue;
				for (final org.bouncycastle.asn1.x509.Attribute claimedRole : signerAttrValueArray) {
					claimedRoles.addAll(getClaimedSignerRoles(claimedRole));
				}
			}
			return claimedRoles;
		} catch (Exception e) {
			LOG.warn("Error when dealing with claimed signer roles : {}", signerAttrValues, e);
			return Collections.emptyList();
		}
	}

	private List<SignerRole> getClaimedSignerRoles(final org.bouncycastle.asn1.x509.Attribute claimedRole) {
		final List<SignerRole> claimedRoles = new ArrayList<>();
		final ASN1Encodable[] attrValues1 = claimedRole.getAttrValues().toArray();
		for (final ASN1Encodable asn1Encodable : attrValues1) {
			if (asn1Encodable instanceof ASN1String) {
				ASN1String asn1String = (ASN1String) asn1Encodable;
				final String role = asn1String.getString();
				claimedRoles.add(new SignerRole(role, EndorsementType.CLAIMED));
			}
		}
		return claimedRoles;
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
			List<SignerRole> roles = new ArrayList<>();
			for (final Object signerAttrValue : signerAttrValues) {
				if (signerAttrValue instanceof AttributeCertificate) {
					roles.addAll(getCertifiedSignerRoles((AttributeCertificate) signerAttrValue));
				}
			}
			return roles;
		} catch (Exception e) {
			LOG.warn("Error when dealing with certified signer roles : {}", signerAttrValues, e);
			return Collections.emptyList();
		}
	}

	private List<SignerRole> getCertifiedSignerRoles(final AttributeCertificate attributeCertificate) {
		List<SignerRole> roles = new ArrayList<>();
		final AttributeCertificateInfo acInfo = attributeCertificate.getAcinfo();
		final AttCertValidityPeriod attrCertValidityPeriod = acInfo.getAttrCertValidityPeriod();
		final ASN1Sequence attributes = acInfo.getAttributes();
		for (int ii = 0; ii < attributes.size(); ii++) {

			final ASN1Encodable objectAt = attributes.getObjectAt(ii);
			final org.bouncycastle.asn1.x509.Attribute attribute = org.bouncycastle.asn1.x509.Attribute.getInstance(objectAt);
			final ASN1Set attrValues1 = attribute.getAttrValues();
			ASN1Encodable firstItem = attrValues1.getObjectAt(0);
			if (firstItem instanceof ASN1Sequence) {
				ASN1Sequence sequence = (ASN1Sequence) firstItem;
				RoleSyntax roleSyntax = RoleSyntax.getInstance(sequence);
				SignerRole certifiedRole = new SignerRole(roleSyntax.getRoleNameAsString(), EndorsementType.CERTIFIED);
				certifiedRole.setNotBefore(DSSASN1Utils.toDate(attrCertValidityPeriod.getNotBeforeTime()));
				certifiedRole.setNotAfter(DSSASN1Utils.toDate(attrCertValidityPeriod.getNotAfterTime()));
				roles.add(certifiedRole);
			} else {
				LOG.warn("Unsupported type for RoleSyntax : {}", firstItem == null ? null : firstItem.getClass().getSimpleName());
			}
		}
		return roles;
	}

	private SignerAttribute getSignerAttributeV1() {
		final Attribute idAaEtsSignerAttr = CAdESUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_signerAttr);
		if (idAaEtsSignerAttr != null) {
			final ASN1Set attrValues = idAaEtsSignerAttr.getAttrValues();
			final ASN1Encodable attrValue = attrValues.getObjectAt(0);
			try {
				return SignerAttribute.getInstance(attrValue);
			} catch (Exception e) {
				String warningMessage = "Unable to parse signerAttr - [{}]. Reason : {}";
				if (LOG.isDebugEnabled()) {
					LOG.warn(warningMessage, Utils.toBase64(DSSASN1Utils.getDEREncoded(attrValue)), e.getMessage(), e);
				} else {
					LOG.warn(warningMessage, Utils.toBase64(DSSASN1Utils.getDEREncoded(attrValue)), e.getMessage());
				}
			}
		}
		return null;
	}

	private SignerAttributeV2 getSignerAttributeV2() {
		final Attribute idAaEtsSignerAttrV2 = CAdESUtils.getSignedAttribute(signerInformation, OID.id_aa_ets_signerAttrV2);
		if (idAaEtsSignerAttrV2 != null) {
			final ASN1Set attrValues = idAaEtsSignerAttrV2.getAttrValues();
			final ASN1Encodable attrValue = attrValues.getObjectAt(0);
			try {
				return SignerAttributeV2.getInstance(attrValue);
			} catch (Exception e) {
				LOG.warn("Unable to parse signerAttrV2 : {}", Utils.toBase64(DSSASN1Utils.getDEREncoded(attrValue)), e);
			}
		}
		return null;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {

		String oid = signerInformation.getEncryptionAlgOID();
		try {
			return EncryptionAlgorithm.forOID(oid);
		} catch (IllegalArgumentException e) {
			// purposely empty
		}

		try {
			// fallback to identify via signature algorithm
			final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(oid);
			return signatureAlgorithm.getEncryptionAlgorithm();
		} catch (IllegalArgumentException e) {
			LOG.warn("Unable to identify encryption algorithm for OID '{}'. Reason : {}", oid, e.getMessage());
		}

		return null;
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		final SignatureAlgorithm signatureAlgorithm = getEncryptedDigestAlgo();
		if (signatureAlgorithm != null) {
			if (EncryptionAlgorithm.RSASSA_PSS.equals(signatureAlgorithm.getEncryptionAlgorithm())) {
				return getPSSHashAlgorithm();
			}
			return signatureAlgorithm.getDigestAlgorithm();

		} else {
			final String digestAlgOID = signerInformation.getDigestAlgOID();
			try {
				return DigestAlgorithm.forOID(digestAlgOID);
			} catch (IllegalArgumentException e) {
				LOG.warn("Unable to identify DigestAlgorithm for OID '{}'. Reason : {}", digestAlgOID, e.getMessage());
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

	private DigestAlgorithm getPSSHashAlgorithm() {
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
	public SignatureAlgorithm getSignatureAlgorithm() {
		return SignatureAlgorithm.getAlgorithm(getEncryptionAlgorithm(), getDigestAlgorithm());
	}

	@Override
	public void checkSignatureIntegrity() {
		if (signatureCryptographicVerification != null) {
			return;
		}
		signatureCryptographicVerification = new SignatureCryptographicVerification();
		try {
			SignerInformation signerInformationToCheck = null;
			if (cms.isDetachedSignature() && !isCounterSignature()) {
				if (Utils.isCollectionEmpty(detachedContents)) {
					signatureCryptographicVerification.setErrorMessage("Detached file not found!");
					getReferenceValidations(signerInformationToCheck);
					return;
				}
				signerInformationToCheck = recreateSignerInformation();
			} else {
				signerInformationToCheck = signerInformation;
			}
			
			CandidatesForSigningCertificate candidatesForSigningCertificate = getCandidatesForSigningCertificate();
			
			SignatureIntegrityValidator signingCertificateValidator = new CAdESSignatureIntegrityValidator(signerInformationToCheck);
			CertificateValidity certificateValidity = signingCertificateValidator.validate(candidatesForSigningCertificate);
			if (certificateValidity != null) {
				candidatesForSigningCertificate.setTheCertificateValidity(certificateValidity);
			}
			
			List<String> errorMessages = signingCertificateValidator.getErrorMessages();
			signatureCryptographicVerification.setErrorMessages(errorMessages);
			signatureCryptographicVerification.setSignatureIntact(certificateValidity != null);

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
			LOG.warn(e.getMessage(), e);
			signatureCryptographicVerification.setErrorMessage(e.getMessage());
		}
		LOG.debug(" - RESULT: {}", signatureCryptographicVerification);
	}

	/**
	 * Returns the reference validation
	 *
	 * @param signerInformationToCheck {@link SignerInformation}
	 * @return a list of {@link ReferenceValidation}s
	 */
	public List<ReferenceValidation> getReferenceValidations(SignerInformation signerInformationToCheck) {
		if (referenceValidations == null) {
			referenceValidations = new ArrayList<>();

			DSSDocument originalDocument = null;
			try {
				originalDocument = getSignerDocumentContent();
			} catch (DSSException e) {
				LOG.warn("Original document not found");
			}

			ReferenceValidation validation;
			final byte[] messageDigestValue = getMessageDigestValue();
			if (messageDigestValue != null) {
				validation = getMessageDigestReferenceValidation(originalDocument, messageDigestValue);
			} else {
				LOG.warn("message-digest is not present in SignedData! Extracting digests from content SignatureValue...");
				validation = getContentReferenceValidation(originalDocument, signerInformationToCheck);
			}

			referenceValidations.add(validation);

		}
		return referenceValidations;
	}

	/**
	 * This method extracts a document content that was signed
	 *
	 * NOTE: Some differences are possible with PAdES
	 *
	 * @return {@link DSSDocument}
	 */
	protected DSSDocument getSignerDocumentContent() {
		return getOriginalDocument();
	}

	private boolean verifyDigestAlgorithm(DSSDocument originalDocument, Set<DigestAlgorithm> messageDigestAlgorithms,
			Digest messageDigest) {
		if (Utils.isCollectionNotEmpty(messageDigestAlgorithms)) {
			// try to match with found digest algorithm(s)
			for (DigestAlgorithm digestAlgorithm : messageDigestAlgorithms) {
				byte[] base64Digest = originalDocument.getDigestValue(digestAlgorithm);
				if (Arrays.equals(messageDigest.getValue(), base64Digest)) {
					messageDigest.setAlgorithm(digestAlgorithm);
					return true;
				}
			}
		} else {
			LOG.warn("Message DigestAlgorithms not found in SignedData! Reference validation is not possible.");
		}

		return false;
	}
	
	private List<ReferenceValidation> getManifestEntryValidation() {
		List<ReferenceValidation> manifestEntryValidations = new ArrayList<>();
		if (manifestFile == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("No related manifest file found for a signature with name [{}]", getFilename());
			}
			return manifestEntryValidations;
		}
		for (ManifestEntry entry : manifestFile.getEntries()) {
			ReferenceValidation entryValidation = new ReferenceValidation();
			entryValidation.setType(DigestMatcherType.MANIFEST_ENTRY);
			entryValidation.setUri(entry.getUri());
			entryValidation.setDocumentName(entry.getDocumentName());
			entryValidation.setDigest(entry.getDigest());
			entryValidation.setFound(entry.isFound());
			entryValidation.setIntact(entry.isIntact());
			manifestEntryValidations.add(entryValidation);
		}
		
		return manifestEntryValidations;
	}

	@Override
	public List<ReferenceValidation> getReferenceValidations() {
		checkSignatureIntegrity();
		return referenceValidations;
	}
	
	/**
	 * Verifies a message-digest of a CMS, when applicable
	 *
	 * @param originalDocument {@link DSSDocument} the signed original document
	 * @param messageDigestValue message-digest byte array content
	 * @return {@link ReferenceValidation}
	 */
	private ReferenceValidation getMessageDigestReferenceValidation(DSSDocument originalDocument, byte[] messageDigestValue) {
		ReferenceValidation messageDigestValidation = new ReferenceValidation();
		messageDigestValidation.setType(DigestMatcherType.MESSAGE_DIGEST);
		
		Digest messageDigest = new Digest();
		messageDigest.setValue(messageDigestValue);
		messageDigestValidation.setDigest(messageDigest);

		Set<DigestAlgorithm> digestAlgorithmCandidates = new HashSet<>();
		DigestAlgorithm signerInformationDigestAlgorithm = getDigestAlgorithm();
		if (signerInformationDigestAlgorithm != null) {
			digestAlgorithmCandidates.add(signerInformationDigestAlgorithm);
		}
		digestAlgorithmCandidates.addAll(getMessageDigestAlgorithms());
		
		if (Utils.collectionSize(digestAlgorithmCandidates) == 1) {
			messageDigest.setAlgorithm(digestAlgorithmCandidates.iterator().next());
		}

		if (originalDocument != null) {
			messageDigestValidation.setDocumentName(originalDocument.getName());
			messageDigestValidation.setFound(true);
			messageDigestValidation.setIntact(verifyDigestAlgorithm(originalDocument, digestAlgorithmCandidates, messageDigest));

			if (manifestFile != null && 
					Arrays.equals(messageDigest.getValue(), manifestFile.getDigestValue(messageDigest.getAlgorithm()))) {
				// get references to documents contained in the manifest file (for ASiC-E container)
				messageDigestValidation.getDependentValidations()
						.addAll(getManifestEntryValidation());
			}
		} else {
			LOG.warn("The original document is not found or cannot be extracted. Reference validation is not possible.");
		}
		return messageDigestValidation;
	}
	
	/**
	 * Verifies a content digest, when applicable
	 *
	 * @param originalDocument {@link DSSDocument} the signed original document
	 * @param signerInformation {@link SignerInformation}
	 * @return {@link ReferenceValidation}
	 */
	private ReferenceValidation getContentReferenceValidation(DSSDocument originalDocument, SignerInformation signerInformation) {
		ReferenceValidation contentValidation = new ReferenceValidation();
		contentValidation.setType(DigestMatcherType.CONTENT_DIGEST);
		if (signerInformation != null) {
			DigestAlgorithm digestAlgorithm = getDigestAlgorithmForOID(signerInformation.getDigestAlgOID());
			if (originalDocument != null && digestAlgorithm != null) {
				byte[] contentDigest = signerInformation.getContentDigest();
				if (Utils.isArrayNotEmpty(contentDigest)) {
					contentValidation.setFound(true);
					contentValidation.setDigest(new Digest(digestAlgorithm, contentDigest));
					if (Arrays.equals(contentDigest, originalDocument.getDigestValue(digestAlgorithm))) {
						contentValidation.setIntact(true);
					}
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
	
	@Override
	public Digest getDataToBeSignedRepresentation() {
		List<ReferenceValidation> referenceValidations = getReferenceValidations();
		ReferenceValidation referenceValidation = referenceValidations.iterator().next(); // only one is allowed for CMS
		switch (referenceValidation.getType()) {
			case MESSAGE_DIGEST:
				DigestAlgorithm digestAlgorithm = getDigestAlgorithm();
				if (digestAlgorithm != null) {
					AttributeTable signedAttributes = CAdESUtils.getSignedAttributes(signerInformation);
					byte[] derEncoded = DSSASN1Utils.getDEREncoded(signedAttributes.toASN1Structure());
					return new Digest(digestAlgorithm, DSSUtils.digest(digestAlgorithm, derEncoded));
				}
				return null;
			case CONTENT_DIGEST:
				return referenceValidation.getDigest();
			default:
				throw new DSSException(String.format("The found referenceValidation type '%s' is not supported! "
						+ "Unable to compute DTBSR.", referenceValidation.getType()));
		}
	}

	/**
	 * This method recreates a {@code SignerInformation} with the content using
	 * a {@code CMSParser}.
	 *
	 * @return {@link SignerInformation}
	 * @throws CMSException if CMS exception occurs
	 * @throws IOException if IOException occurs
	 */
	private SignerInformation recreateSignerInformation() throws CMSException, IOException {
		final DSSDocument dssDocument = detachedContents.get(0); // only one element for CAdES Signature
		PrecomputedDigestCalculatorProvider digestCalculatorProvider = new PrecomputedDigestCalculatorProvider(dssDocument);
		return CMSUtils.recomputeSignerInformation(cms, getSignerId(), digestCalculatorProvider, CAdESUtils.DEFAULT_RESOURCES_HANDLER_BUILDER);
	}

	/**
	 * Returns a set of used {@link DigestAlgorithm}s incorporated into the CMS
	 *
	 * @return a set of {@link DigestAlgorithm}s
	 */
	public Set<DigestAlgorithm> getMessageDigestAlgorithms() {
		Set<DigestAlgorithm> result = new HashSet<>();
		Set<AlgorithmIdentifier> digestAlgorithmIDs = cms.getDigestAlgorithmIDs();
		for (AlgorithmIdentifier algorithmIdentifier : digestAlgorithmIDs) {
			String oid = algorithmIdentifier.getAlgorithm().getId();
			DigestAlgorithm digestAlgorithm = getDigestAlgorithmForOID(oid);
			if (digestAlgorithm != null) {
				result.add(digestAlgorithm);
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

	/**
	 * Returns a digest value incorporated in an attribute "message-digest" in CMS
	 * Signed Data
	 * 
	 * @return a byte array representing a signed content digest value
	 */
	public byte[] getMessageDigestValue() {
		final Attribute messageDigestAttribute = CAdESUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.pkcs_9_at_messageDigest);
		if (messageDigestAttribute == null) {
			return null;
		}
		final ASN1OctetString asn1OctetString = (ASN1OctetString) messageDigestAttribute.getAttrValues().getObjectAt(0);
		return asn1OctetString.getOctets();
	}

	@Override
	public String getContentType() {
		final Attribute contentTypeAttribute = CAdESUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.pkcs_9_at_contentType);
		if (contentTypeAttribute == null) {
			return null;
		}
		final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) contentTypeAttribute.getAttrValues().getObjectAt(0);
		return oid.getId();
	}

	@Override
	public String getMimeType() {
		final Attribute mimeTypeAttribute = CAdESUtils.getSignedAttribute(signerInformation, OID.id_aa_ets_mimeType);
		if (mimeTypeAttribute == null) {
			return null;
		}
		return DSSASN1Utils.getString(mimeTypeAttribute.getAttrValues().getObjectAt(0));
	}

	/**
	 * Gets ContentIdentifier String
	 *
	 * @return content identifier as {@code String}
	 */
	public String getContentIdentifier() {
		final Attribute contentIdentifierAttribute = CAdESUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_contentIdentifier);
		if (contentIdentifierAttribute == null) {
			return null;
		}
		final ASN1Encodable asn1Encodable = contentIdentifierAttribute.getAttrValues().getObjectAt(0);
		final ContentIdentifier contentIdentifier = ContentIdentifier.getInstance(asn1Encodable);
		return DSSASN1Utils.toString(contentIdentifier.getValue());
	}

	/**
	 * Gets Content Hints
	 *
	 * @return content hints as {@code String}
	 */
	public String getContentHints() {
		final Attribute contentHintAttribute = CAdESUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_contentHint);
		if (contentHintAttribute == null) {
			return null;
		}
		final ASN1Encodable asn1Encodable = contentHintAttribute.getAttrValues().getObjectAt(0);
		String contentHint = null;
		try {
			final ContentHints contentHints = ContentHints.getInstance(asn1Encodable);
			if (contentHints != null) {
				// content-type is mandatory
				contentHint = contentHints.getContentType().toString();
				// content-description is optional
				if (contentHints.getContentDescriptionUTF8() != null) {
					contentHint += " [" + contentHints.getContentDescriptionUTF8().toString() + "]";
				}
			}
		} catch (Exception e) {
			String warningMessage = "Unable to parse ContentHints - [{}]. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(warningMessage, Utils.toBase64(DSSASN1Utils.getDEREncoded(asn1Encodable)), e.getMessage(), e);
			} else {
				LOG.warn(warningMessage, Utils.toBase64(DSSASN1Utils.getDEREncoded(asn1Encodable)), e.getMessage());
			}
		}

		return contentHint;
	}

	/**
	 * Gets a SignedInformation
	 *
	 * @return {@link SignerInformation} the signerInformation
	 */
	public SignerInformation getSignerInformation() {
		return signerInformation;
	}
	
	@Override
	public byte[] getSignatureValue() {
		return signerInformation.getSignature();
	}
	
	@Override
	public boolean isCounterSignature() {
		return signerInformation.isCounterSignature();
	}

	@Override
	public List<AdvancedSignature> getCounterSignatures() {
		if (counterSignatures != null) {
			return counterSignatures;
		}
		
		counterSignatures = new ArrayList<>();
		for (final SignerInformation counterSignerInformation : getCounterSignatureStore()) {
			final CAdESSignature counterSignature = new CAdESSignature(cms, counterSignerInformation);
			counterSignature.setFilename(getFilename());
			counterSignature.setMasterSignature(this);
			counterSignatures.add(counterSignature);
		}
		return counterSignatures;
	}
	
	/**
	 * Returns a SignerInformationStore containing counter signatures
	 * 
	 * @return {@link SignerInformationStore}
	 */
	protected SignerInformationStore getCounterSignatureStore() {
		if (counterSignaturesStore == null) {
			counterSignaturesStore = signerInformation.getCounterSignatures();
		}
		return counterSignaturesStore;
	}

	/**
	 * Returns the original signed document
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getOriginalDocument() {
		// RFC 5652 ch 11.4.
		if (isCounterSignature()) {
			return new InMemoryDocument(getMasterSignature().getSignatureValue());
		}

		return CAdESUtils.getOriginalDocument(cms, detachedContents);
	}
	
	@Override
	protected SignatureIdentifierBuilder getSignatureIdentifierBuilder() {
		return new CAdESSignatureIdentifierBuilder(this);
	}
	
	@Override
	public String getDAIdentifier() {
		// not applicable for CAdES
		return null;
	}

	/**
	 * Returns a Set of CertificateIdentifier extracted from a
	 * SignerInformationStore of CMS Signed Data
	 * 
	 * @return a Set of {@link SignerIdentifier}s
	 */
	public Set<SignerIdentifier> getSignerInformationStoreInfos() {
		return getCertificateSource().getAllCertificateIdentifiers();
	}

	@Override
	public void addExternalTimestamp(TimestampToken timestamp) {
		if (!timestamp.isProcessed()) {
			throw new DSSException("Timestamp token must be validated first !");
		}
		getTimestampSource().addExternalTimestamp(timestamp);
	}

	@Override
	public SignatureLevel getDataFoundUpToLevel() {
		if (!hasBESProfile()) {
			return SignatureLevel.CMS_NOT_ETSI;
		}

		boolean baselineProfile = hasBProfile();

		if (!hasExtendedTProfile()) {
			if (baselineProfile) {
				return SignatureLevel.CAdES_BASELINE_B;
			} else if (hasEPESProfile()) {
				return SignatureLevel.CAdES_EPES;
			}
			return SignatureLevel.CAdES_BES;
		}

		baselineProfile = baselineProfile && hasTProfile();

		if (baselineProfile && hasLTProfile()) {
			if (hasLTAProfile()) {
				return SignatureLevel.CAdES_BASELINE_LTA;
			}
			return SignatureLevel.CAdES_BASELINE_LT;

		} else if (hasCProfile()) {
			if (hasXLProfile()) {
				if (hasAProfile()) {
					return SignatureLevel.CAdES_A;
				}
				if (hasXProfile()) {
					return SignatureLevel.CAdES_XL;
				}
			}
			if (hasXProfile()) {
				return SignatureLevel.CAdES_X;
			}
			return SignatureLevel.CAdES_C;

		} else if (hasXLProfile()) {
			if (hasAProfile()) {
				return SignatureLevel.CAdES_A; // CAdES-E-A can be built on CAdES-E-T directly
			}
			return SignatureLevel.CAdES_LT;
		}

		return baselineProfile ? SignatureLevel.CAdES_BASELINE_T : SignatureLevel.CAdES_T;
	}

	@Override
	protected CAdESBaselineRequirementsChecker getBaselineRequirementsChecker() {
		return (CAdESBaselineRequirementsChecker) super.getBaselineRequirementsChecker();
	}

	@Override
	protected CAdESBaselineRequirementsChecker createBaselineRequirementsChecker(CertificateVerifier certificateVerifier) {
		return new CAdESBaselineRequirementsChecker(this, certificateVerifier);
	}

}
