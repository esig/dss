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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.signature.HttpHeadersPayloadBuilder;
import eu.europa.esig.dss.jades.validation.scope.JAdESSignatureScopeFinder;
import eu.europa.esig.dss.jades.validation.timestamp.JAdESTimestampSource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.model.signature.CommitmentTypeIndication;
import eu.europa.esig.dss.spi.signature.DefaultAdvancedSignature;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.model.signature.SignatureDigestReference;
import eu.europa.esig.dss.spi.signature.identifier.SignatureIdentifierBuilder;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.model.signature.SignatureProductionPlace;
import eu.europa.esig.dss.model.signature.SignerRole;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.jose4j.jwx.HeaderParameterNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents the JAdES signature
 */
public class JAdESSignature extends DefaultAdvancedSignature {

	private static final long serialVersionUID = -3730351687600398811L;

	private static final Logger LOG = LoggerFactory.getLogger(JAdESSignature.class);

	/** The JWS signature object */
	private final JWS jws;
	
	/** Defines if the validating signature is detached */
	private final boolean isDetached;
	
	/**
	 * The 'cSig' object embedding the current signature
	 * 
	 * NOTE: used for counter signatures only
	 */
	private EtsiUComponent masterCSigComponent;

	/** The list of unsigned properties embedded into the 'etsiU' array */
	private JAdESEtsiUHeader etsiUHeader;

	/**
	 * Default constructor
	 *
	 * @param jws {@link JWS}
	 */
	public JAdESSignature(JWS jws) {
		this.jws = jws;
		this.isDetached = Utils.isArrayEmpty(jws.getUnverifiedPayloadBytes());
	}

	/**
	 * Gets the associated {@code JWS}
	 *
	 * @return {@link JWS}
	 */
	public JWS getJws() {
		return jws;
	}

	@Override
	public SignatureForm getSignatureForm() {
		return SignatureForm.JAdES;
	}

	@Override
	public SignatureAlgorithm getSignatureAlgorithm() {
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forJWA(jws.getAlgorithmHeaderValue(), null);
		if (signatureAlgorithm == null) {
			LOG.warn("SignatureAlgorithm '{}' is not supported!", jws.getAlgorithmHeaderValue());
		} else if (EncryptionAlgorithm.EDDSA.equals(signatureAlgorithm.getEncryptionAlgorithm())) {
			signatureAlgorithm = DSSUtils.getEdDSASignatureAlgorithm(getSignatureValue());
		}
		return signatureAlgorithm;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
		if (signatureAlgorithm == null) {
			return null;
		}
		return signatureAlgorithm.getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
		if (signatureAlgorithm == null) {
			return null;
		}
		return signatureAlgorithm.getDigestAlgorithm();
	}

	@Override
	@Deprecated
	public MaskGenerationFunction getMaskGenerationFunction() {
		EncryptionAlgorithm encryptionAlgorithm = getEncryptionAlgorithm();
		if (EncryptionAlgorithm.RSASSA_PSS == encryptionAlgorithm) {
			return MaskGenerationFunction.MGF1;
		}
		return null;
	}

	@Override
	public Date getSigningTime() {
		Number iat = jws.getProtectedHeaderValueAsNumber(JAdESHeaderParameterNames.IAT);
		String sigT = jws.getProtectedHeaderValueAsString(JAdESHeaderParameterNames.SIG_T);
		if (iat != null && Utils.isStringNotEmpty(sigT)) {
			LOG.debug("Unable to extract claimed signing-time: Conflict between 'iat' and 'sigT' header parameters! " +
					"Only one shall be present.");
			return null;
		} else if (iat != null) {
			return DSSJsonUtils.getDate(iat);
		} else if (Utils.isStringNotEmpty(sigT)) {
			return DSSJsonUtils.getDate(sigT);
		}
		LOG.debug("Unable to extract claimed signing-time: No signing-time identifying header was found.");
		return null;
	}

	/**
	 * Checks if the JAdES Signature is a detached (contains 'sigD' dictionary)
	 * 
	 * @return TRUE if the signature is detached, FALSE otherwise
	 */
	public boolean isDetachedSignature() {
		return isDetached;
	}

	/**
	 * Gets a 'cSig' component embedding the current signature
	 * 
	 * @return {@link EtsiUComponent} 'cSig' embedding the current signature
	 */
	public EtsiUComponent getMasterCSigComponent() {
		return masterCSigComponent;
	}

	/**
	 * Sets a 'cSig' component embedding the current signature
	 * 
	 * @param masterCSigComponent {@link Object} 'cSig' embedding the current
	 *                            signature
	 */
	public void setMasterCSigComponent(EtsiUComponent masterCSigComponent) {
		this.masterCSigComponent = masterCSigComponent;
	}

	@Override
	public SignatureCertificateSource getCertificateSource() {
		if (offlineCertificateSource == null) {
			offlineCertificateSource = new JAdESCertificateSource(jws, getEtsiUHeader());
		}
		return offlineCertificateSource;
	}

	@Override
	public OfflineCRLSource getCRLSource() {
		if (signatureCRLSource == null) {
			signatureCRLSource = new JAdESCRLSource(getEtsiUHeader());
		}
		return signatureCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {
		if (signatureOCSPSource == null) {
			signatureOCSPSource = new JAdESOCSPSource(getEtsiUHeader());
		}
		return signatureOCSPSource;
	}

	@Override
	public JAdESTimestampSource getTimestampSource() {
		if (signatureTimestampSource == null) {
			signatureTimestampSource = new JAdESTimestampSource(this);
		}
		return (JAdESTimestampSource) signatureTimestampSource;
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {
		Map<?, ?> signaturePlace = jws.getProtectedHeaderValueAsMap(JAdESHeaderParameterNames.SIG_PL);
		if (Utils.isMapNotEmpty(signaturePlace)) {
			SignatureProductionPlace result = new SignatureProductionPlace();
			result.setCity(DSSJsonUtils.getAsString(signaturePlace, JAdESHeaderParameterNames.ADDRESS_LOCALITY));
			result.setStreetAddress(DSSJsonUtils.getAsString(signaturePlace, JAdESHeaderParameterNames.STREET_ADDRESS));
			result.setPostOfficeBoxNumber(DSSJsonUtils.getAsString(signaturePlace, JAdESHeaderParameterNames.POST_OFFICE_BOX_NUMBER));
			result.setPostalCode(DSSJsonUtils.getAsString(signaturePlace, JAdESHeaderParameterNames.POSTAL_CODE));
			result.setStateOrProvince(DSSJsonUtils.getAsString(signaturePlace, JAdESHeaderParameterNames.ADDRESS_REGION));
			result.setCountryName(DSSJsonUtils.getAsString(signaturePlace, JAdESHeaderParameterNames.ADDRESS_COUNTRY));
			return result;
		}
		return null;
	}

	@Override
	public SignaturePolicyStore getSignaturePolicyStore() {
		try {
			Map<?, ?> sigPStMap = getUnsignedPropertyAsMap(JAdESHeaderParameterNames.SIG_PST);
			if (Utils.isMapNotEmpty(sigPStMap)) {
				SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();

				String sigPolDocBase64 = DSSJsonUtils.getAsString(sigPStMap, JAdESHeaderParameterNames.SIG_POL_DOC);
				if (Utils.isStringNotEmpty(sigPolDocBase64)) {
					DSSDocument policyContent = new InMemoryDocument(Utils.fromBase64(sigPolDocBase64));
					signaturePolicyStore.setSignaturePolicyContent(policyContent);
				}

				String sigPolLocalURI = DSSJsonUtils.getAsString(sigPStMap, JAdESHeaderParameterNames.SIG_POL_LOCAL_URI);
				if (Utils.isStringNotEmpty(sigPolLocalURI)) {
					signaturePolicyStore.setSigPolDocLocalURI(sigPolLocalURI);
				}

				Object spDSpec = sigPStMap.get(JAdESHeaderParameterNames.SP_DSPEC);
				if (spDSpec != null) {
					SpDocSpecification spDocSpecification = DSSJsonUtils.parseSPDocSpecification(spDSpec);
					signaturePolicyStore.setSpDocSpecification(spDocSpecification);
				}

				return signaturePolicyStore;
			}

		} catch (Exception e) {
			LOG.warn("Cannot read signature policy store : {}", e.getMessage(), e);
		}
		return null;
	}

	@Override
	public List<CommitmentTypeIndication> getCommitmentTypeIndications() {
		List<CommitmentTypeIndication> result = new ArrayList<>();
		List<?> signedCommitments = jws.getProtectedHeaderValueAsList(JAdESHeaderParameterNames.SR_CMS);
		if (Utils.isCollectionNotEmpty(signedCommitments)) {
			for (Object signedCommitment : signedCommitments) {
				Map<?, ?> signedCommitmentMap = DSSJsonUtils.toMap(signedCommitment);
				if (Utils.isMapNotEmpty(signedCommitmentMap)) {
					Map<?, ?> commIdMap = DSSJsonUtils.getAsMap(signedCommitmentMap, JAdESHeaderParameterNames.COMM_ID);
					if (Utils.isMapNotEmpty(commIdMap)) {
						String uri = DSSJsonUtils.getAsString(commIdMap, JAdESHeaderParameterNames.ID);
						uri = DSSUtils.getObjectIdentifierValue(uri);
						if (Utils.isStringNotBlank(uri)) {
							CommitmentTypeIndication commitmentTypeIndication = new CommitmentTypeIndication(uri);
							String desc = DSSJsonUtils.getAsString(commIdMap, JAdESHeaderParameterNames.DESC);
							commitmentTypeIndication.setDescription(desc);
							List<?> docRefs = DSSJsonUtils.getAsList(commIdMap, JAdESHeaderParameterNames.DOC_REFS);
							commitmentTypeIndication.setDocumentReferences(DSSJsonUtils.toListOfStrings(docRefs));
							result.add(commitmentTypeIndication);

						} else {
							LOG.warn("Id parameter in the OID with the value '{}' is not conformant! The entry is skipped.", uri);
						}
					}
				}
			}
		}
		return result;
	}

	@Override
	public String getContentType() {
		// not applicable for JAdES (see TS 119 102-2 v1.4.1)
		return null;
	}

	@Override
	public String getMimeType() {
		/*
		 * TS 119 102-2 v1.4.1 :
		 * The MimeType element shall contain the value of cty header parameter, prefixed with the string "application/"
		 * when this prefix has been omitted in the cty header parameter.
		 */
		String value = jws.getContentTypeHeaderValue();
		/*
		 * NOTE: The sigD header parameter has one member that contains information of the format and type of the
		 * constituents of the JWS Payload.
		 */
		if (Utils.isStringEmpty(value)) {
			// sigD: return the first one when present
			List<String> ctys = getSignedDataContentTypeList();
			if (Utils.isCollectionNotEmpty(ctys)) {
				value = ctys.get(0);
			}
		}
		if (Utils.isStringNotEmpty(value)) {
			return DSSJsonUtils.getMimeTypeString(value);
		}
		return null;
	}

	/**
	 * Returns value of the "typ" header parameter, declaring the media type of the JWS, when present.
	 *
	 * @return {@link String}
	 */
	public String getSignatureType() {
		String value = jws.getProtectedHeaderValueAsString(HeaderParameterNames.TYPE);
		if (Utils.isStringNotEmpty(value)) {
			return DSSJsonUtils.getMimeTypeString(value);
		}
		return null;
	}

	@Override
	public List<SignerRole> getCertifiedSignerRoles() {
		List<SignerRole> result = new ArrayList<>();
		Map<?, ?> signerAttributes = getSignerAttributes();
		if (Utils.isMapNotEmpty(signerAttributes)) {
			List<?> certified = DSSJsonUtils.getAsList(signerAttributes, JAdESHeaderParameterNames.CERTIFIED);
			if (Utils.isCollectionNotEmpty(certified)) {
				for (Object certifiedItem : certified) {
					String certifiedVal = getCertifiedVal(certifiedItem);
					if (Utils.isStringNotEmpty(certifiedVal)) {
						result.add(new SignerRole(certifiedVal, EndorsementType.CERTIFIED));
					}
				}
			}
		}
		return result;
	}

	private String getCertifiedVal(Object certifiedItem) {
		Map<?, ?> certifiedItemMap = DSSJsonUtils.toMap(certifiedItem, JAdESHeaderParameterNames.CERTIFIED_ATTRS);

		Map<?, ?> x509AttrCert = DSSJsonUtils.getAsMap(certifiedItemMap, JAdESHeaderParameterNames.X509_ATTR_CERT);
		if (Utils.isMapNotEmpty(x509AttrCert)) {
			return DSSJsonUtils.getAsString(x509AttrCert, JAdESHeaderParameterNames.VAL);
		}

		Map<?, ?> otherAttrCert = DSSJsonUtils.getAsMap(certifiedItemMap, JAdESHeaderParameterNames.OTHER_ATTR_CERT);
		if (Utils.isMapNotEmpty(otherAttrCert)) {
			LOG.warn("Unsupported {} found", JAdESHeaderParameterNames.OTHER_ATTR_CERT);
			return null;
		}

		LOG.warn("One of types {} or {} is expected in {}", JAdESHeaderParameterNames.X509_ATTR_CERT,
				JAdESHeaderParameterNames.OTHER_ATTR_CERT, JAdESHeaderParameterNames.CERTIFIED);

		return null;
	}

	@Override
	public List<SignerRole> getClaimedSignerRoles() {
		Map<?, ?> signerAttributes = getSignerAttributes();
		if (Utils.isMapNotEmpty(signerAttributes)) {
			List<?> claimed = DSSJsonUtils.getAsList(signerAttributes, JAdESHeaderParameterNames.CLAIMED);
			if (Utils.isCollectionNotEmpty(claimed)) {
				return getQArraySignerRoles(claimed, EndorsementType.CLAIMED);
			}
		}
		return Collections.emptyList();
	}

	@Override
	public List<SignerRole> getSignedAssertions() {
		Map<?, ?> signerAttributes = getSignerAttributes();
		if (Utils.isMapNotEmpty(signerAttributes)) {
			List<?> signedAssertions = DSSJsonUtils.getAsList(signerAttributes, JAdESHeaderParameterNames.SIGNED_ASSERTIONS);
			if (Utils.isCollectionNotEmpty(signedAssertions)) {
				return getQArraySignerRoles(signedAssertions, EndorsementType.SIGNED);
			}
		}
		return Collections.emptyList();
	}

	private List<SignerRole> getQArraySignerRoles(List<?> qArrays, EndorsementType category) {
		List<SignerRole> result = new ArrayList<>();
		
		if (Utils.isCollectionNotEmpty(qArrays)) {
			for (Object qArray : qArrays) {
				Map<?, ?> qArrayMap = DSSJsonUtils.toMap(qArray);
				List<?> vals = DSSJsonUtils.getAsList(qArrayMap, JAdESHeaderParameterNames.Q_VALS);
				for (Object val : vals) {
					result.add(new SignerRole(val.toString(), category));
				}

			}
		}
		return result;
	}

	private Map<?, ?> getSignerAttributes() {
		return jws.getProtectedHeaderValueAsMap(JAdESHeaderParameterNames.SR_ATS);
	}

	@Override
	public List<AdvancedSignature> getCounterSignatures() {
		if (counterSignatures != null) {
			return counterSignatures;
		}
		counterSignatures = new ArrayList<>();
		
		List<EtsiUComponent> etsiUComponents = getEtsiUHeader().getAttributes();
		if (Utils.isCollectionNotEmpty(etsiUComponents)) {
			for (EtsiUComponent etsiUComponent : etsiUComponents) {
				if (JAdESHeaderParameterNames.C_SIG.equals(etsiUComponent.getHeaderName())) {
					JAdESSignature counterSignature = DSSJsonUtils.extractJAdESCounterSignature(etsiUComponent, this);
					if (counterSignature != null) {
						counterSignature.setSignatureFilename(getSignatureFilename());
						counterSignatures.add(counterSignature);
					}
				}
			}
		}
		return counterSignatures;
	}

	@Override
	public String getDAIdentifier() {
		// not applicable for JAdES
		return null;
	}

	@Override
	protected SignaturePolicy buildSignaturePolicy() {
		Map<?, ?> sigPolicy = jws.getProtectedHeaderValueAsMap(JAdESHeaderParameterNames.SIG_PID);
		if (Utils.isMapNotEmpty(sigPolicy)) {
			Map<?, ?> policyId = DSSJsonUtils.getAsMap(sigPolicy, JAdESHeaderParameterNames.ID);
			if (Utils.isMapNotEmpty(policyId)) {
				String id = DSSJsonUtils.getAsString(policyId, JAdESHeaderParameterNames.ID);
				signaturePolicy = new SignaturePolicy(DSSUtils.getObjectIdentifierValue(id));
				String desc = DSSJsonUtils.getAsString(policyId, JAdESHeaderParameterNames.DESC);
				signaturePolicy.setDescription(desc);
				List<?> docRefs = DSSJsonUtils.getAsList(policyId, JAdESHeaderParameterNames.DOC_REFS);
				signaturePolicy.setDocumentationReferences(DSSJsonUtils.toListOfStrings(docRefs));

				signaturePolicy.setDigest(DSSJsonUtils.getDigest(sigPolicy));

				List<?> qualifiers = DSSJsonUtils.getAsList(sigPolicy, JAdESHeaderParameterNames.SIG_P_QUALS);
				if (Utils.isCollectionNotEmpty(qualifiers)) {
					signaturePolicy.setUri(getSPUri(qualifiers));
					signaturePolicy.setUserNotice(getSPUserNotice(qualifiers));
					signaturePolicy.setDocSpecification(getSPDSpec(qualifiers));
				}

				Boolean digPSp = DSSJsonUtils.getAsBoolean(sigPolicy, JAdESHeaderParameterNames.DIG_PSP);
				if (digPSp != null) {
					signaturePolicy.setHashAsInTechnicalSpecification(digPSp);
				}
			}

		}
		return signaturePolicy;
	}

	private String getSPUri(List<?> qualifiers) {
		for (Object qualifier : qualifiers) {
			Map<?, ?> qualifierMap = DSSJsonUtils.toMap(qualifier, JAdESHeaderParameterNames.SIG_P_QUAL);
			if (Utils.isMapNotEmpty(qualifierMap)) {
				String spUri = DSSJsonUtils.getAsString(qualifierMap, JAdESHeaderParameterNames.SP_URI);
				if (Utils.isStringNotEmpty(spUri)) {
					return spUri;
				}
			}
		}
		return null;
	}

	private UserNotice getSPUserNotice(List<?> qualifiers) {
		for (Object qualifier : qualifiers) {
			Map<?, ?> qualifierMap = DSSJsonUtils.toMap(qualifier, JAdESHeaderParameterNames.SIG_P_QUAL);
			if (Utils.isMapNotEmpty(qualifierMap)) {
				Map<?, ?> spUserNotice = DSSJsonUtils.getAsMap(qualifierMap, JAdESHeaderParameterNames.SP_USER_NOTICE);
				if (Utils.isMapNotEmpty(spUserNotice)) {
					try {
						final UserNotice userNotice = new UserNotice();

						final Map<?, ?> noticeRef = DSSJsonUtils.getAsMap(spUserNotice, JAdESHeaderParameterNames.NOTICE_REF);
						if (Utils.isMapNotEmpty(noticeRef)) {
							final String organization = DSSJsonUtils.getAsString(noticeRef, JAdESHeaderParameterNames.ORGANTIZATION);
							if (Utils.isStringNotBlank(organization)) {
								userNotice.setOrganization(organization);
							}

							final List<?> noticeNumbers = DSSJsonUtils.getAsList(noticeRef, JAdESHeaderParameterNames.NOTICE_NUMBERS);
							if (Utils.isCollectionNotEmpty(noticeNumbers)) {
								userNotice.setNoticeNumbers(DSSJsonUtils.toListOfNumbers(noticeNumbers)
										.stream().mapToInt(Number::intValue).toArray());
							}
						}
						final String explTest = DSSJsonUtils.getAsString(spUserNotice, JAdESHeaderParameterNames.EXPL_TEXT);
						if (Utils.isStringNotBlank(explTest)) {
							userNotice.setExplicitText(explTest);
						}
						return userNotice;

					} catch (Exception e) {
						LOG.warn("Unable to build SPUserNotice qualifier. Reason : {}", e.getMessage(), e);
						return null;
					}
				}
			}
		}
		return null;
	}

	private SpDocSpecification getSPDSpec(List<?> qualifiers) {
		for (Object qualifier : qualifiers) {
			Map<?, ?> qualifierMap = DSSJsonUtils.toMap(qualifier, JAdESHeaderParameterNames.SIG_P_QUAL);
			if (Utils.isMapNotEmpty(qualifierMap)) {
				Object spDSpec = qualifierMap.get(JAdESHeaderParameterNames.SP_DSPEC);
				if (spDSpec != null) {
					return DSSJsonUtils.parseSPDocSpecification(spDSpec);
				}
			}
		}
		return null;
	}

	@Override
	public byte[] getSignatureValue() {
		return jws.getSignatureValue();
	}

	/**
	 * Returns unsigned properties embedded into the 'etsiU' array
	 * 
	 * @return {@link JAdESEtsiUHeader}
	 */
	public JAdESEtsiUHeader getEtsiUHeader() {
		if (etsiUHeader == null) {
			etsiUHeader = new JAdESEtsiUHeader(jws);
		}
		return etsiUHeader;
	}

	// TODO : no definition available in ETSI TS 119 442 - V1.1.1
	@Override
	public SignatureDigestReference getSignatureDigestReference(DigestAlgorithm digestAlgorithm) {
		String encodedHeader = jws.getEncodedHeader();
		String payload = jws.isRfc7797UnencodedPayload() ? jws.getUnverifiedPayload() : jws.getEncodedPayload();
		String encodedSignature = jws.getEncodedSignature();
		byte[] signatureReferenceBytes = DSSJsonUtils.concatenate(encodedHeader, payload, encodedSignature).getBytes();
		byte[] digestValue = DSSUtils.digest(digestAlgorithm, signatureReferenceBytes);
		return new SignatureDigestReference(new Digest(digestAlgorithm, digestValue));
	}
	
	@Override
	public Digest getDataToBeSignedRepresentation() {
		List<ReferenceValidation> referenceValidations = getReferenceValidations();
		for (ReferenceValidation referenceValidation : referenceValidations) {
			if (DigestMatcherType.JWS_SIGNING_INPUT_DIGEST.equals(referenceValidation.getType())) {
				return referenceValidation.isFound() ? referenceValidation.getDigest() : null;
			}
		}
		// shall not happen
		throw new DSSException("JWS_SIGNING_INPUT_DIGEST is not found! Unable to compute DTBSR.");
	}

	@Override
	protected SignatureIdentifierBuilder getSignatureIdentifierBuilder() {
		return new JAdESSignatureIdentifierBuilder(this);
	}

	@Override
	public void checkSignatureIntegrity() {

		if (signatureCryptographicVerification != null) {
			return;
		}
		
		signatureCryptographicVerification = new SignatureCryptographicVerification();

		boolean refsFound = false;
		boolean refsIntact = false;
		
		List<ReferenceValidation> referenceValidations = getReferenceValidations();
		
		if (Utils.isCollectionNotEmpty(referenceValidations)) {
			refsFound = true;
			refsIntact = true;
			
			for (ReferenceValidation referenceValidation : referenceValidations) {
				if (DigestMatcherType.JWS_SIGNING_INPUT_DIGEST.equals(referenceValidation.getType())) {
					JAdESReferenceValidation signingInputReferenceValidation = (JAdESReferenceValidation) referenceValidation;
					signatureCryptographicVerification.setSignatureIntact(signingInputReferenceValidation.isIntact());
					
					for (String errorMessage : signingInputReferenceValidation.getErrorMessages()) {
						signatureCryptographicVerification.setErrorMessage(errorMessage);
					}
				}
				refsFound = refsFound && referenceValidation.isFound();
				refsIntact = refsIntact && referenceValidation.isIntact();
			}
		}
		
		signatureCryptographicVerification.setReferenceDataFound(refsFound);
		signatureCryptographicVerification.setReferenceDataIntact(refsIntact);

	}

	@Override
	public List<ReferenceValidation> getReferenceValidations() {
		if (referenceValidations == null) {
			referenceValidations = new ArrayList<>();
			
			JAdESReferenceValidation signingInputReferenceValidation = getSigningInputReferenceValidation();
			referenceValidations.add(signingInputReferenceValidation);

			if (isDetachedSignature()) {
				List<JAdESReferenceValidation> detachedReferenceValidations = getDetachedReferenceValidations();
				if (Utils.isCollectionNotEmpty(detachedReferenceValidations)) {
					referenceValidations.addAll(detachedReferenceValidations);
				}
			}

			if (isCounterSignature()) {
				referenceValidations.add(getCounterSignatureReferenceValidation());
			}
			
		}
		return referenceValidations;
	}
	
	private JAdESReferenceValidation getSigningInputReferenceValidation() {
		JAdESReferenceValidation signatureValueReferenceValidation = new JAdESReferenceValidation();
		signatureValueReferenceValidation.setType(DigestMatcherType.JWS_SIGNING_INPUT_DIGEST);
		
		try {
			String encodedHeader = jws.getEncodedHeader();
			if (Utils.isStringNotEmpty(encodedHeader)) {
				// get payload for a detached signature
				try {
					SigDMechanism sigDMechanism = getSigDMechanism();
					boolean detachedContentPresent = Utils.isCollectionNotEmpty(detachedContents);
					if (!isDetachedSignature()) {
						// not detached
						signatureValueReferenceValidation.setFound(true);

					} else if (sigDMechanism == null && detachedContentPresent) {
						// simple detached signature
						byte[] payload = getIncorporatedPayload();
						jws.setPayloadOctets(payload);
						signatureValueReferenceValidation.setFound(detachedContents.size() == 1);

					} else if (SigDMechanism.HTTP_HEADERS.equals(sigDMechanism)) {
						// detached with HTTP_HEADERS mechanism
						byte[] payload = getPayloadForHttpHeadersMechanism();
						jws.setPayloadOctets(payload);
						signatureValueReferenceValidation.setFound(payload != null);

					} else if (SigDMechanism.OBJECT_ID_BY_URI.equals(sigDMechanism)) {
						// detached with OBJECT_ID_BY_URI mechanism
						byte[] payload = getPayloadForObjectIdByUriMechanism();
						jws.setPayloadOctets(payload);
						signatureValueReferenceValidation.setFound(payload != null);

					} else if (SigDMechanism.OBJECT_ID_BY_URI_HASH.equals(sigDMechanism)) {
						// the sigD itself is signed with OBJECT_ID_BY_URI_HASH mechanism
						signatureValueReferenceValidation.setFound(true);

					} else {
						// otherwise original content is not found
						LOG.warn("The payload is not found! The detached content must be provided!");
					}

				} catch (Exception e) {
					String errorMessage = "Unable to determine a JWS payload. Reason : {}";
					if (LOG.isDebugEnabled()) {
						LOG.warn(errorMessage, e.getMessage(), e);
					} else {
						LOG.warn(errorMessage, e.getMessage());
					}
				}

				SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
				if (signatureAlgorithm != null) {
					byte[] dataToSign = DSSJsonUtils.getSigningInputBytes(jws);
					DigestAlgorithm digestAlgorithm = signatureAlgorithm.getDigestAlgorithm();
					Digest digest = new Digest(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign));
					signatureValueReferenceValidation.setDigest(digest);

					jws.setDoKeyValidation(false); // restrict on key size,...
	
					CandidatesForSigningCertificate candidatesForSigningCertificate = getCandidatesForSigningCertificate();
					
					SignatureIntegrityValidator signingCertificateValidator = new JAdESSignatureIntegrityValidator(jws);
					CertificateValidity certificateValidity = signingCertificateValidator.validate(candidatesForSigningCertificate);
					if (certificateValidity != null) {
						candidatesForSigningCertificate.setTheCertificateValidity(certificateValidity);
					}
					
					List<String> errorMessages = signingCertificateValidator.getErrorMessages();
					signatureValueReferenceValidation.setErrorMessages(errorMessages);
					signatureValueReferenceValidation.setIntact(certificateValidity != null);
				}
			}
			
		} catch (Exception e) {
			LOG.warn("The validation of signed input failed! Reason : {}", e.getMessage(), e);
		}
		
		return signatureValueReferenceValidation;
	}

	/**
	 * Gets Kid value when present
	 *
	 * @return {@link String}
	 */
	public String getKid() {
		return jws.getKeyIdHeaderValue();
	}

	private List<JAdESReferenceValidation> getDetachedReferenceValidations() {
		SigDMechanism sigDMechanism = getSigDMechanism();
		if (sigDMechanism != null) {
			switch (sigDMechanism) {
				case HTTP_HEADERS:
				case OBJECT_ID_BY_URI:
					// the documents are added to the payload, not possible to extract separate reference validations
					break;
				case OBJECT_ID_BY_URI_HASH:
					return getReferenceValidationsByUriHashMechanism();
				default:
					LOG.warn("The SigDMechanism '{}' is not supported!", sigDMechanism);
					break;
			}
		}
		return Collections.emptyList();
	}
	
	/**
	 * Returns a mechanism used in 'sigD' to cover a detached content
	 * 
	 * @return {@link SigDMechanism}
	 */
	public SigDMechanism getSigDMechanism() {
		Map<?, ?> signatureDetached = jws.getProtectedHeaderValueAsMap(JAdESHeaderParameterNames.SIG_D);
		if (Utils.isMapNotEmpty(signatureDetached)) {
			String mechanismUri = DSSJsonUtils.getAsString(signatureDetached, JAdESHeaderParameterNames.M_ID);
			SigDMechanism sigDMechanism = SigDMechanism.forUri(mechanismUri);
			if (sigDMechanism == null) {
				LOG.warn("The sigDMechanism with uri '{}' is not supported!", mechanismUri);
			}
			return sigDMechanism;
		}
		return null;
	}

	private byte[] getIncorporatedPayload() {
		return DSSJsonUtils.getDocumentOctets(detachedContents.get(0), !jws.isRfc7797UnencodedPayload());
	}
	
	private byte[] getPayloadForHttpHeadersMechanism() {
		if (Utils.isCollectionEmpty(detachedContents)) {
			throw new IllegalArgumentException("The detached contents shall be provided for validating a detached signature!");
		}
		
		/*
		 * Case-insensitive, see TS 119 182-1 "5.2.8.2	Mechanism HttpHeaders":
		 *
		 * For this referencing mechanism, the contents of the pars member shall be
		 * an array of lowercased names of HTTP header fields, each one with the semantics
		 * and syntax specified in clause 2.1.3 of draft-cavage-http-signatures-10:
		 * "Signing HTTP Messages" [17].
		 */
		List<DSSDocument> documentsByUri = getSignedDocumentsByHTTPHeaderName();
		HttpHeadersPayloadBuilder httpHeadersPayloadBuilder = new HttpHeadersPayloadBuilder(documentsByUri, false);
		
		return httpHeadersPayloadBuilder.build();
	}
	
	/**
	 * Returns a list of signed documents by the list of URIs present in 'sigD'
	 * Keeps the original order according to 'pars' dictionary content
	 * Used in HTTPHeaders detached signature mechanism
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignedDocumentsByHTTPHeaderName() {
		List<String> signedDataUriList = getSignedDataUriList();
		
		if (Utils.isCollectionEmpty(detachedContents)) {
			LOG.warn("Detached content is not provided!");
			return Collections.emptyList();
		}
		
		if (signedDataUriList.size() == 1 && detachedContents.size() == 1) {
			return detachedContents;
		}
		
		List<DSSDocument> signedDocuments = new ArrayList<>();
		for (String signedDataName : signedDataUriList) {
			boolean found = false;
			for (DSSDocument document : detachedContents) {
				if (Utils.areStringsEqualIgnoreCase(signedDataName, document.getName())) {
					found = true;
					signedDocuments.add(document);
					// do not break - same name docs possible
				}
			}
			if (!found) {
				throw new IllegalArgumentException(String.format(
						"The detached content for a signed data with name '%s' has not been found!", signedDataName));
			}
		}
		
		return signedDocuments;
	}
	
	private byte[] getPayloadForObjectIdByUriMechanism() {
		if (Utils.isCollectionEmpty(detachedContents)) {
			throw new IllegalArgumentException("The detached contents shall be provided for validating a detached signature!");
		}

		List<DSSDocument> signedDocumentsByUri = getSignedDocumentsForObjectIdByUriMechanism();
		return DSSJsonUtils.concatenateDSSDocuments(signedDocumentsByUri, !jws.isRfc7797UnencodedPayload());
	}

	/**
	 * This method returns a list of documents for ObjectIdByUrl or ObjectIdByUriHash mechanisms
	 * Keeps the original order according to 'pars' dictionary content
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignedDocumentsForObjectIdByUriMechanism() {
		List<String> signedDataUriList = getSignedDataUriList();
		List<DSSDocument> signedDocumentsByUri = Collections.emptyList();
		if (Utils.collectionSize(signedDataUriList) == 1 && Utils.collectionSize(detachedContents) == 1) {
			signedDocumentsByUri = Collections.singletonList(detachedContents.iterator().next());

		} else if (Utils.isCollectionNotEmpty(signedDataUriList)) {
			signedDocumentsByUri = new ArrayList<>();
			for (String signedDataName : signedDataUriList) {
				DSSDocument detachedDocumentByName = getDetachedDocumentByName(signedDataName, detachedContents);
				if (detachedDocumentByName != null) {
					signedDocumentsByUri.add(detachedDocumentByName);
				} else {
					throw new IllegalArgumentException(String.format(
							"The detached content for a signed data with name '%s' has not been found!", signedDataName));
				}
			}
		}
		return signedDocumentsByUri;
	}
	
	private List<JAdESReferenceValidation> getReferenceValidationsByUriHashMechanism() {
		List<DSSDocument> detachedDocuments = detachedContents;
		
		if (Utils.isCollectionEmpty(detachedContents)) {
			LOG.warn("The detached content is not provided! Validation of '{}' is not possible.", JAdESHeaderParameterNames.SIG_D);
			detachedDocuments = Collections.emptyList();
			// continue in order to extract signed data references
		}
		
		Map<String, String> signedDataHashMap = getSignedDataUriHashMap();
		if (Utils.isMapEmpty(signedDataHashMap)) {
			LOG.warn("The SignedData has not been found or incorrect for detached content.");
			JAdESReferenceValidation emptyReference = new JAdESReferenceValidation();
			emptyReference.setType(DigestMatcherType.SIG_D_ENTRY);
			return Collections.singletonList(emptyReference);
		}

		DigestAlgorithm digestAlgorithm = getDigestAlgorithmForDetachedContent();
		if (digestAlgorithm == null) {
			LOG.warn("The DigestAlgorithm has not been found for the detached content.");
		}
		
		List<JAdESReferenceValidation> detachedReferenceValidations = new ArrayList<>();

		for (Map.Entry<String, String> signedDataEntry : signedDataHashMap.entrySet()) {
			JAdESReferenceValidation referenceValidation = new JAdESReferenceValidation();
			referenceValidation.setType(DigestMatcherType.SIG_D_ENTRY);
			
			String signedDataName = signedDataEntry.getKey();
			referenceValidation.setUri(signedDataName);
			
			String expectedDigestString = signedDataEntry.getValue();
			byte[] expectedDigest = DSSJsonUtils.fromBase64Url(expectedDigestString);
			if (digestAlgorithm != null) {
				referenceValidation.setDigest(new Digest(digestAlgorithm, expectedDigest));
			}

			DSSDocument detachedDocument;
			if (Utils.collectionSize(signedDataHashMap.entrySet()) == 1 && Utils.collectionSize(detachedDocuments) == 1) {
				detachedDocument = detachedDocuments.iterator().next();
			} else {
				detachedDocument = getDetachedDocumentByDigest(digestAlgorithm, expectedDigest, detachedDocuments);
				if (detachedDocument == null) {
					detachedDocument = getDetachedDocumentByName(signedDataName, detachedDocuments);
				}
			}

			if (detachedDocument != null) {
				referenceValidation.setFound(true);
				referenceValidation.setDocumentName(detachedDocument.getName());
				if (digestAlgorithm != null && isDocumentDigestMatch(detachedDocument, digestAlgorithm, expectedDigest)) {
					referenceValidation.setIntact(true);
				}
			} else {
				LOG.warn("A detached document for the '{}' header with name '{}' has not been found!",
						JAdESHeaderParameterNames.SIG_D, signedDataName);
			}
			
			detachedReferenceValidations.add(referenceValidation);
		}
		
		if (Utils.isCollectionEmpty(detachedReferenceValidations)) {
			// add an empty reference if none found
			JAdESReferenceValidation referenceValidation = new JAdESReferenceValidation();
			referenceValidation.setType(DigestMatcherType.SIG_D_ENTRY);
			detachedReferenceValidations.add(referenceValidation);
		}
		
		return detachedReferenceValidations;
	}
	
	private DigestAlgorithm getDigestAlgorithmForDetachedContent() {
		try {
			Map<?, ?> signatureDetached = jws.getProtectedHeaderValueAsMap(JAdESHeaderParameterNames.SIG_D);
			if (Utils.isMapNotEmpty(signatureDetached)) {
				String digestAlgoUri = DSSJsonUtils.getAsString(signatureDetached, JAdESHeaderParameterNames.HASH_M);
				return DigestAlgorithm.forJAdES(digestAlgoUri);
			}

		} catch (Exception e) {
			String errorMessage = "Unable to extract DigestAlgorithm for '{}' element. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, JAdESHeaderParameterNames.SIG_D, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, JAdESHeaderParameterNames.SIG_D, e.getMessage());
			}
		}
		return null;
	}

	private DSSDocument getDetachedDocumentByDigest(DigestAlgorithm digestAlgorithm, byte[] expectedDigest, List<DSSDocument> detachedContent) {
		if (digestAlgorithm == null || expectedDigest == null) {
			return null;
		}
		for (DSSDocument detachedDocument : detachedContent) {
			if (isDocumentDigestMatch(detachedDocument, digestAlgorithm, expectedDigest)) {
				return detachedDocument;
			}
		}
		return null;
	}

	private DSSDocument getDetachedDocumentByName(String documentName, List<DSSDocument> detachedContent) {
		documentName = DSSUtils.decodeURI(documentName);
		for (DSSDocument detachedDocument : detachedContent) {
			if (documentName.equals(detachedDocument.getName())) {
				return detachedDocument;
			}
		}
		return null;
	}

	private Map<String, String> getSignedDataUriHashMap() {
		Map<String, String> signedDataHashMap = new LinkedHashMap<>(); // LinkedHashMap is used to keep the original order
		
		List<String> signedDataUriList = getSignedDataUriList();
		List<String> signedDataHashList = getSignedDataHashList();
		if (signedDataUriList.size() != signedDataHashList.size()) {
			LOG.warn("The size of 'pars' and 'hashV' dictionaries does not match! See '5.2.8 The sigD header parameter'.");
			return signedDataHashMap;
		}
		
		for (int ii = 0; ii < signedDataUriList.size(); ii++) {
			signedDataHashMap.put(signedDataUriList.get(ii), signedDataHashList.get(ii));
		}
		return signedDataHashMap;
	}

	private List<String> getSignedDataUriList() {
		Map<?, ?> signatureDetached = jws.getProtectedHeaderValueAsMap(JAdESHeaderParameterNames.SIG_D);
		if (Utils.isMapNotEmpty(signatureDetached)) {
			List<?> pars = DSSJsonUtils.getAsList(signatureDetached, JAdESHeaderParameterNames.PARS);
			return DSSJsonUtils.toListOfStrings(pars);
		}
		return Collections.emptyList();
	}

	private List<String> getSignedDataHashList() {
		Map<?, ?> signatureDetached = jws.getProtectedHeaderValueAsMap(JAdESHeaderParameterNames.SIG_D);
		if (Utils.isMapNotEmpty(signatureDetached)) {
			List<?> pars = DSSJsonUtils.getAsList(signatureDetached, JAdESHeaderParameterNames.HASH_V);
			return DSSJsonUtils.toListOfStrings(pars);
		}
		return Collections.emptyList();
	}

	private List<String> getSignedDataContentTypeList() {
		Map<?, ?> signatureDetached = jws.getProtectedHeaderValueAsMap(JAdESHeaderParameterNames.SIG_D);
		if (Utils.isMapNotEmpty(signatureDetached)) {
			List<?> pars = DSSJsonUtils.getAsList(signatureDetached, JAdESHeaderParameterNames.CTYS);
			return DSSJsonUtils.toListOfStrings(pars);
		}
		return Collections.emptyList();
	}
	
	private boolean isDocumentDigestMatch(DSSDocument document, DigestAlgorithm digestAlgorithm,
			byte[] expectedDigest) {
		byte[] computedDigestValue;
		if (jws.isRfc7797UnencodedPayload() || document instanceof DigestDocument) {
			computedDigestValue = document.getDigestValue(digestAlgorithm);
		} else {
			String base64UrlEncodedDocument = DSSJsonUtils.toBase64Url(document);
			computedDigestValue = DSSUtils.digest(digestAlgorithm, base64UrlEncodedDocument.getBytes());
		}

		if (Arrays.equals(expectedDigest, computedDigestValue)) {
			return true;
		}
		LOG.warn("The computed digest '{}' from a document with name '{}' does not match one provided on the sigD : {}!", 
				DSSJsonUtils.toBase64Url(computedDigestValue), document.getName(), DSSJsonUtils.toBase64Url(expectedDigest));
		return false;
	}

	private JAdESReferenceValidation getCounterSignatureReferenceValidation() {
		JAdESReferenceValidation referenceValidation = new JAdESReferenceValidation();
		referenceValidation.setType(DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE);

		JAdESSignature masterSignature = (JAdESSignature) getMasterSignature();
		if (masterSignature != null) {

			byte[] signatureValue = masterSignature.getJws().getSignatureValue();
			if (Utils.isArrayNotEmpty(signatureValue)) {
				referenceValidation.setFound(true);
			}

			byte[] unverifiedPayloadBytes = getJws().getUnverifiedPayloadBytes();
			if (Utils.isArrayNotEmpty(unverifiedPayloadBytes)) {
				boolean intact = Arrays.equals(signatureValue, unverifiedPayloadBytes);
				if (!intact) {
					LOG.warn("The payload of a cSig with Id '{}' does not match the signature value of its master signature!",
							getDSSId().asXmlId());
				}
				referenceValidation.setIntact(intact);
			} else {
				// nothing to compare against for an attached signature
				referenceValidation.setIntact(true);
			}

		}

		return referenceValidation;
	}
	
	private Map<?, ?> getUnsignedPropertyAsMap(String headerName) {
		List<EtsiUComponent> unsignedPropertiesWithHeaderName = 
				DSSJsonUtils.getUnsignedPropertiesWithHeaderName(getEtsiUHeader(), headerName);
		if (Utils.isCollectionNotEmpty(unsignedPropertiesWithHeaderName)) {
			// return the first occurrence
			return DSSJsonUtils.toMap(unsignedPropertiesWithHeaderName.iterator().next().getValue(), headerName);
		}
		return null;
	}

	/**
	 * Returns a list of original documents signed by the signature
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getOriginalDocuments() {
		if (isDetachedSignature()) {
			
			List<DSSDocument> originalDocuments = new ArrayList<>();
			
			List<ReferenceValidation> referenceValidations = getReferenceValidations();
			for (ReferenceValidation referenceValidation : referenceValidations) {
				if (DigestMatcherType.SIG_D_ENTRY.equals(referenceValidation.getType()) && referenceValidation.isIntact()) {
					String signedDataName = DSSUtils.decodeURI(referenceValidation.getUri());
					DSSDocument detachedDocument = getDetachedDocumentByName(signedDataName, detachedContents);
					if (detachedDocument != null) {
						originalDocuments.add(detachedDocument);
					}
				}
			}
			
			if (Utils.isCollectionEmpty(originalDocuments)) {
				// check if the signature of an old detached format
				SignatureCryptographicVerification signatureCryptographicVerification = getSignatureCryptographicVerification();
				if (signatureCryptographicVerification.isSignatureIntact()) {
					if (Utils.isCollectionNotEmpty(detachedContents) && detachedContents.size() == 1) {
						return Collections.singletonList(detachedContents.get(0));
						
					} else if (SigDMechanism.HTTP_HEADERS.equals(getSigDMechanism())) {
						return getSignedDocumentsByHTTPHeaderName();
								
					} else if (SigDMechanism.OBJECT_ID_BY_URI.equals(getSigDMechanism())) {
						return getSignedDocumentsForObjectIdByUriMechanism();
								
					}
				} 
			}
			
			return originalDocuments;
			
		} else {
			byte[] payloadBytes = jws.getUnverifiedPayloadBytes();
			return Collections.singletonList(new InMemoryDocument(payloadBytes));
		}
	}

	@Override
	public SignatureLevel getDataFoundUpToLevel() {
		if (!hasBProfile()) {
			return SignatureLevel.JSON_NOT_ETSI;
		}
		if (!hasTProfile()) {
			return SignatureLevel.JAdES_BASELINE_B;
		}
		if (hasLTProfile()) {
			if (hasLTAProfile()) {
				return SignatureLevel.JAdES_BASELINE_LTA;
			}
			return SignatureLevel.JAdES_BASELINE_LT;
		}
		return SignatureLevel.JAdES_BASELINE_T;
	}

	@Override
	protected JAdESBaselineRequirementsChecker createBaselineRequirementsChecker(CertificateVerifier certificateVerifier) {
		return new JAdESBaselineRequirementsChecker(this, certificateVerifier);
	}
	
	@Override
	protected List<String> validateStructure() {
		List<String> validationErrors = DSSJsonUtils.validateAgainstJAdESSchema(jws);
		if (Utils.isCollectionNotEmpty(validationErrors)) {
			LOG.warn("Error(s) occurred during the JSON schema validation : {}", validationErrors);
		}
		return validationErrors;
	}

	@Override
	protected List<SignatureScope> findSignatureScopes() {
		return new JAdESSignatureScopeFinder().findSignatureScope(this);
	}

	@Override
	public void addExternalTimestamp(TimestampToken timestamp) {
		throw new UnsupportedOperationException("The method addExternalTimestamp(timestamp) is not supported for JAdES!");
	}

}
