package eu.europa.esig.dss.jades.validation;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CandidatesForSigningCertificate;
import eu.europa.esig.dss.validation.CertificateValidity;
import eu.europa.esig.dss.validation.CommitmentTypeIndication;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.SignatureDigestReference;
import eu.europa.esig.dss.validation.SignatureIdentifier;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.SignerRole;

public class JAdESSignature extends DefaultAdvancedSignature {

	private static final long serialVersionUID = -3730351687600398811L;

	private static final Logger LOG = LoggerFactory.getLogger(JAdESSignature.class);

	/* Format date-time as specified in RFC 3339 5.6 */
	private static final String DATE_TIME_FORMAT_RFC3339 = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	private final JWS jws;

	public JAdESSignature(JWS jws) {
		this.jws = jws;
	}

	public JWS getJws() {
		return jws;
	}

	@Override
	public SignatureForm getSignatureForm() {
		return SignatureForm.JAdES;
	}

	@Override
	public SignatureAlgorithm getSignatureAlgorithm() {
		return SignatureAlgorithm.forJWA(jws.getAlgorithmHeaderValue());
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return getSignatureAlgorithm().getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		return getSignatureAlgorithm().getDigestAlgorithm();
	}

	@Override
	public MaskGenerationFunction getMaskGenerationFunction() {
		return getSignatureAlgorithm().getMaskGenerationFunction();
	}

	@Override
	public Date getSigningTime() {
		String signingTimeStr = jws.getHeaders().getStringHeaderValue(JAdESHeaderParameterNames.SIG_T);
		if (Utils.isStringNotEmpty(signingTimeStr)) {
			try {
				SimpleDateFormat sdf = new SimpleDateFormat(DATE_TIME_FORMAT_RFC3339);
				sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
				return sdf.parse(signingTimeStr);
			} catch (ParseException e) {
				LOG.warn("Unable to parse {} with value '{}' : {}", JAdESHeaderParameterNames.SIG_T, signingTimeStr,
						e.getMessage());
			}
		}
		return null;
	}

	@Override
	public SignatureCertificateSource getCertificateSource() {
		if (offlineCertificateSource == null) {
			offlineCertificateSource = new JAdESCertificateSource(jws);
		}
		return offlineCertificateSource;
	}

	@Override
	public OfflineCRLSource getCRLSource() {
		if (signatureCRLSource == null) {
			signatureCRLSource = new JAdESCRLSource();
		}
		return signatureCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {
		if (signatureOCSPSource == null) {
			signatureOCSPSource = new JAdESOCSPSource();
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
	public void checkSignatureIntegrity() {

		if (signatureCryptographicVerification != null) {
			return;
		}
		signatureCryptographicVerification = new SignatureCryptographicVerification();
		boolean coreValidity = false;

		CandidatesForSigningCertificate candidates = getCandidatesForSigningCertificate();
		if (candidates.isEmpty()) {
			signatureCryptographicVerification
					.setErrorMessage("There is no signing certificate within the signature or certificate pool.");
		}

		jws.setKnownCriticalHeaders(JAdESUtils.getSupportedCriticalHeaders());
		jws.setDoKeyValidation(false); // restrict on key size,...

		LOG.debug("Determining signing certificate from certificate candidates list...");
		final List<String> preliminaryErrorMessages = new ArrayList<>();
		int certificateNumber = 0;
		for (CertificateValidity certificateValidity : candidates.getCertificateValidityList()) {
			String errorMessagePrefix = "Certificate #" + (certificateNumber + 1) + ": ";

			jws.setKey(certificateValidity.getPublicKey());

			try {
				coreValidity = jws.verifySignature();
				if (coreValidity) {
					LOG.info("Determining signing certificate from certificate candidates list succeeded");
					candidates.setTheCertificateValidity(certificateValidity);
					break;
				}
			} catch (JoseException e) {
				LOG.debug("Exception while probing candidate certificate as signing certificate: {}", e.getMessage());
				preliminaryErrorMessages.add(errorMessagePrefix + e.getMessage());
			}

			certificateNumber++;
		}

		if (!coreValidity) {
			LOG.warn("Determining signing certificate from certificate candidates list failed: {}",
					preliminaryErrorMessages);
			for (String preliminaryErrorMessage : preliminaryErrorMessages) {
				signatureCryptographicVerification.setErrorMessage(preliminaryErrorMessage);
			}
		}

		signatureCryptographicVerification.setSignatureIntact(coreValidity);

	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {
		Map<?, ?> signaturePlace = (Map<?, ?>) jws.getHeaders()
				.getObjectHeaderValue(JAdESHeaderParameterNames.SIG_PL);
		if (signaturePlace != null) {
			SignatureProductionPlace result = new SignatureProductionPlace();
			result.setCity((String) signaturePlace.get(JAdESHeaderParameterNames.CITY));
			result.setStreetAddress((String) signaturePlace.get(JAdESHeaderParameterNames.STR_ADDR));
			result.setPostalCode((String) signaturePlace.get(JAdESHeaderParameterNames.POST_CODE));
			result.setStateOrProvince((String) signaturePlace.get(JAdESHeaderParameterNames.STAT_PROV));
			result.setCountryName((String) signaturePlace.get(JAdESHeaderParameterNames.COUNTRY));
			return result;
		}
		return null;
	}

	@Override
	public List<CommitmentTypeIndication> getCommitmentTypeIndications() {
		List<CommitmentTypeIndication> result = new ArrayList<>();
		Map<?, ?> signedCommitment = (Map<?, ?>) jws.getHeaders()
				.getObjectHeaderValue(JAdESHeaderParameterNames.SR_CM);
		if (signedCommitment != null) {
			Map<? ,?> commIdMap = (Map<? ,?>) signedCommitment.get(JAdESHeaderParameterNames.COMM_ID);
			String id = getIdFromOidMap(commIdMap);
			if (Utils.isStringNotEmpty(id)) {
				result.add(new CommitmentTypeIndication(id));
			}
		}
		return result;
	}
	
	private String getIdFromOidMap(Map<? ,?> oidMap) {
		if (Utils.isMapNotEmpty(oidMap)) {
			Object idObject = oidMap.get(JAdESHeaderParameterNames.ID);
			if (idObject instanceof String) {
				return (String) idObject;
			} else {
				LOG.warn("Id paramater in the OID is not an instance of String! The value is skipped.");
			}
		}
		return null;
	}

	@Override
	public String getContentType() {
		// TODO handle sigD
		return jws.getContentTypeHeaderValue();
	}

	@Override
	public String getMimeType() {
		return jws.getHeaders().getStringHeaderValue(HeaderParameterNames.TYPE);
	}

	@Override
	public String getContentIdentifier() {
		// not applicable
		return null;
	}

	@Override
	public String getContentHints() {
		// not applicable
		return null;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<SignerRole> getClaimedSignerRoles() {
		List<SignerRole> result = new ArrayList<>();
		Map<?, ?> jsonMap = getSignerAttributes();
		if (jsonMap != null) {
			List<String> claimedList = (List<String>) jsonMap.get(JAdESHeaderParameterNames.CLAIMED);
			if (Utils.isCollectionNotEmpty(claimedList)) {
				for (String claimedBase64 : claimedList) {
					// TODO unclear standard
					String claimed = new String(Utils.fromBase64(claimedBase64));
					result.add(new SignerRole(claimed, EndorsementType.CLAIMED));
				}
			}
		}
		return result;
	}

	@Override
	public List<SignerRole> getCertifiedSignerRoles() {
		List<SignerRole> certifieds = new ArrayList<>();
		Map<?, ?> jsonMap = getSignerAttributes();
		if (jsonMap != null) {
			List<?> certified = (List<?>) jsonMap.get(JAdESHeaderParameterNames.CERTIFIED);
			if (Utils.isCollectionNotEmpty(certified)) {
				// TODO unclear standard
				LOG.info("Attribute {} is detected", JAdESHeaderParameterNames.CERTIFIED);
			}
		}
		return certifieds;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<SignerRole> getSignedAssertions() {
		List<SignerRole> result = new ArrayList<>();
		Map<?, ?> jsonMap = getSignerAttributes();
		if (jsonMap != null) {
			List<String> signedAssertionsList = (List<String>) jsonMap.get(JAdESHeaderParameterNames.SIGNED_ASSERTIONS);
			if (Utils.isCollectionNotEmpty(signedAssertionsList)) {
				for (String signedAssertionBase64 : signedAssertionsList) {
					String signedAssertion = new String(Utils.fromBase64(signedAssertionBase64));
					result.add(new SignerRole(signedAssertion, EndorsementType.SIGNED));
				}
			}
		}
		return result;
	}

	private Map<?, ?> getSignerAttributes() {
		return (Map<?, ?>) jws.getHeaders().getObjectHeaderValue(JAdESHeaderParameterNames.SR_ATS);
	}

	@Override
	public List<AdvancedSignature> getCounterSignatures() {
		// not supported
		return Collections.emptyList();
	}

	@Override
	public String getDAIdentifier() {
		// not applicable for JAdES
		return null;
	}

	@Override
	public SignatureLevel[] getSignatureLevels() {
		return new SignatureLevel[] { SignatureLevel.JSON_NOT_ETSI, SignatureLevel.JAdES_BASELINE_B };
	}

	@Override
	@SuppressWarnings("unchecked")
	public void checkSignaturePolicy(SignaturePolicyProvider signaturePolicyDetector) {
		Map<String, Object> sigPolicy = (Map<String, Object>) jws.getHeaders().getObjectHeaderValue(JAdESHeaderParameterNames.SIG_PID);
		if (Utils.isMapNotEmpty(sigPolicy)) {
			Map<String, Object> policyId = (Map<String, Object>) sigPolicy.get(JAdESHeaderParameterNames.ID);
			String id = (String) policyId.get(JAdESHeaderParameterNames.ID);

			signaturePolicy = new SignaturePolicy(DSSUtils.getOidCode(id));
			signaturePolicy.setDescription((String) policyId.get(JAdESHeaderParameterNames.DESC));
			signaturePolicy.setDigest(JAdESUtils.getDigest((Map<?, ?>) sigPolicy.get(JAdESHeaderParameterNames.HASH_AV)));

			List<Object> qualifiers = (List<Object>) sigPolicy.get(JAdESHeaderParameterNames.SIG_PQUALS);
			if (Utils.isCollectionNotEmpty(qualifiers)) {
				signaturePolicy.setUrl(getSPUri(qualifiers));
			}
		}
	}

	@SuppressWarnings("unchecked")
	private String getSPUri(List<Object> qualifiers) {
		for (Object qualifier : qualifiers) {
			Map<String, Object> qualiferMap = (Map<String, Object>) qualifier;
			String spUri = (String)qualiferMap.get(JAdESHeaderParameterNames.SP_URI);
			if (Utils.isStringNotEmpty(spUri)) {
				return spUri;
			}
		}
		return null;
	}

	@Override
	public byte[] getSignatureValue() {
		return jws.getSignatureValue();
	}

	@Override
	public List<ReferenceValidation> getReferenceValidations() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SignatureDigestReference getSignatureDigestReference(DigestAlgorithm digestAlgorithm) {
		Digest digest = new Digest(digestAlgorithm, jws.getEncodedHeader().getBytes());
		return new SignatureDigestReference(digest);
	}

	@Override
	protected SignatureIdentifier buildSignatureIdentifier() {
		return new JAdESSignatureIdentifier(this);
	}

	public DSSDocument getOriginalDocument() {
		return new InMemoryDocument(jws.getUnverifiedPayloadBytes());
	}

	@Override
	public SignatureLevel getDataFoundUpToLevel() {
		if (!hasBProfile()) {
			return SignatureLevel.JSON_NOT_ETSI;
		}
		return SignatureLevel.JAdES_BASELINE_B;
	}

	private boolean hasBProfile() {
		return getSigningTime() != null && getSignatureAlgorithm() != null;
	}

}
