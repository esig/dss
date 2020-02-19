package eu.europa.esig.dss.jades.validation;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import org.bouncycastle.asn1.x509.IssuerSerial;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CandidatesForSigningCertificate;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.CertificateValidity;
import eu.europa.esig.dss.validation.CommitmentType;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.SignatureCRLSource;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.SignatureDigestReference;
import eu.europa.esig.dss.validation.SignatureIdentifier;
import eu.europa.esig.dss.validation.SignatureOCSPSource;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.SignerRole;
import eu.europa.esig.dss.validation.timestamp.SignatureTimestampSource;

public class JAdESSignature extends DefaultAdvancedSignature {

	private static final long serialVersionUID = -3730351687600398811L;

	private static final Logger LOG = LoggerFactory.getLogger(JAdESSignature.class);

	/* Format date-time as specified in RFC 3339 5.6 */
	private static final String DATE_TIME_FORMAT_RFC3339 = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	private final CustomJsonWebSignature jws;

	public JAdESSignature(CustomJsonWebSignature jws, CertificatePool certPool) {
		super(certPool);
		this.jws = jws;
	}

	public CustomJsonWebSignature getJws() {
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
			offlineCertificateSource = new JAdESCertificateSource(jws, certPool);
		}
		return offlineCertificateSource;
	}

	@Override
	public SignatureCRLSource getCRLSource() {
		if (signatureCRLSource == null) {
			signatureCRLSource = new JAdESCRLSource();
		}
		return signatureCRLSource;
	}

	@Override
	public SignatureOCSPSource getOCSPSource() {
		if (signatureOCSPSource == null) {
			signatureOCSPSource = new JAdESOCSPSource();
		}
		return signatureOCSPSource;
	}

	@Override
	public SignatureTimestampSource getTimestampSource() {
		if (signatureTimestampSource == null) {
			signatureTimestampSource = new JAdESTimestampSource(this, certPool);
		}
		return signatureTimestampSource;
	}

	@Override
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate() {

		if (candidatesForSigningCertificate != null) {
			return candidatesForSigningCertificate;
		}

		candidatesForSigningCertificate = new CandidatesForSigningCertificate();

		final SignatureCertificateSource certSource = getCertificateSource();
		for (final CertificateToken certificateToken : certSource.getKeyInfoCertificates()) {
			candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
		}

		if (providedSigningCertificateToken != null) {
			candidatesForSigningCertificate.add(new CertificateValidity(providedSigningCertificateToken));
		}

		return candidatesForSigningCertificate;
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

			jws.setKey(certificateValidity.getCertificateToken().getPublicKey());

			try {
				coreValidity = jws.verifySignature();
				if (coreValidity) {
					LOG.info("Determining signing certificate from certificate candidates list succeeded");
					candidatesForSigningCertificate.setTheCertificateValidity(certificateValidity);
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
	public void checkSigningCertificate() {

		getCandidatesForSigningCertificate();

		Digest signingCertificateDigest = getSigningCertificateDigest();
		IssuerSerial issuerSerial = getCurrentIssuerSerial();

		for (CertificateValidity certificateValidity : candidatesForSigningCertificate.getCertificateValidityList()) {
			CertificateToken candidate = certificateValidity.getCertificateToken();

			if (signingCertificateDigest != null) {
				certificateValidity.setAttributePresent(true);
				certificateValidity.setDigestPresent(true);

				byte[] candidateDigest = candidate.getDigest(signingCertificateDigest.getAlgorithm());
				if (Arrays.equals(signingCertificateDigest.getValue(), candidateDigest)) {
					certificateValidity.setDigestEqual(true);
					candidatesForSigningCertificate.setTheCertificateValidity(certificateValidity);
				}
			}

			if (issuerSerial != null) {
				IssuerSerial candidateIssuerSerial = DSSASN1Utils.getIssuerSerial(candidate);

				if (issuerSerial.getIssuer().equals(candidateIssuerSerial.getIssuer())) {
					certificateValidity.setDistinguishedNameEqual(true);
				}

				if (issuerSerial.getSerial().equals(candidateIssuerSerial.getSerial())) {
					certificateValidity.setSerialNumberEqual(true);
				}
			}
		}
	}

	private Digest getSigningCertificateDigest() {
		List<CertificateRef> signingCertificates = getCertificateSource().getSigningCertificateValues();
		if (Utils.isCollectionNotEmpty(signingCertificates)) {

			// first is the signing certificate
			CertificateRef designatedSigningCertificate = signingCertificates.iterator().next();
			return designatedSigningCertificate.getCertDigest();
		}
		return null;
	}

	private IssuerSerial getCurrentIssuerSerial() {
		String kid = jws.getKeyIdHeaderValue();
		if (Utils.isStringNotEmpty(kid) && Utils.isBase64Encoded(kid)) {
			byte[] binary = Utils.fromBase64(kid);
			return DSSASN1Utils.getIssuerSerial(binary);
		}
		return null;
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {
		JSONObject signaturePlace = (JSONObject) jws.getHeaders()
				.getObjectHeaderValue(JAdESHeaderParameterNames.SIG_PL);
		if (signaturePlace != null) {
			SignatureProductionPlace result = new SignatureProductionPlace();
			result.setCity((String) signaturePlace.get(JAdESHeaderParameterNames.CITY));
			result.setPostalCode((String) signaturePlace.get(JAdESHeaderParameterNames.POST_CODE));
			result.setStateOrProvince((String) signaturePlace.get(JAdESHeaderParameterNames.STAT_PROV));
			result.setCountryName((String) signaturePlace.get(JAdESHeaderParameterNames.COUNTRY));
			return result;
		}
		return null;
	}

	@Override
	public CommitmentType getCommitmentTypeIndication() {
		JSONObject signedCommitment = (JSONObject) jws.getHeaders()
				.getObjectHeaderValue(JAdESHeaderParameterNames.SR_CM);
		if (signedCommitment != null) {
			String identifier = (String) signedCommitment.get(JAdESHeaderParameterNames.COMM_ID);
			if (Utils.isStringNotEmpty(identifier)) {
				CommitmentType result = new CommitmentType();
				result.addIdentifier(identifier);
				return result;
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
	public List<SignerRole> getClaimedSignerRoles() {
		List<SignerRole> claimeds = new ArrayList<>();
		JSONObject jsonObject = getSignerAttributes();
		if (jsonObject != null) {
			JSONArray array = (JSONArray) jsonObject.get(JAdESHeaderParameterNames.CLAIMED);
			if (Utils.isCollectionNotEmpty(array)) {
				// TODO unclear standard
				LOG.info("Attribute {} is detected", JAdESHeaderParameterNames.CLAIMED);
			}
		}
		return claimeds;
	}

	@Override
	public List<SignerRole> getCertifiedSignerRoles() {
		List<SignerRole> certifieds = new ArrayList<>();
		JSONObject jsonObject = getSignerAttributes();
		if (jsonObject != null) {
			JSONArray array = (JSONArray) jsonObject.get(JAdESHeaderParameterNames.CERTIFIED);
			if (Utils.isCollectionNotEmpty(array)) {
				// TODO unclear standard
				LOG.info("Attribute {} is detected", JAdESHeaderParameterNames.CERTIFIED);
			}
		}
		return certifieds;
	}

	private JSONObject getSignerAttributes() {
		return (JSONObject) jws.getHeaders().getObjectHeaderValue(JAdESHeaderParameterNames.SR_ATS);
	}

	@Override
	public List<AdvancedSignature> getCounterSignatures() {
		// not supported
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getCertificateRefs() {
		// not supported
		return Collections.emptyList();
	}

	@Override
	public String getDAIdentifier() {
		// not applicable for JAdES
		return null;
	}

	@Override
	public boolean isDataForSignatureLevelPresent(SignatureLevel signatureLevel) {
		boolean dataForProfilePresent = true;
		switch (signatureLevel) {
		case JAdES_BASELINE_B:
			dataForProfilePresent = getSigningTime() != null && getSignatureAlgorithm() != null;
			break;
		case JSON_NOT_ETSI:
			dataForProfilePresent = true;
			break;
		default:
			throw new IllegalArgumentException("Unknown level " + signatureLevel);
		}
		return dataForProfilePresent;
	}

	@Override
	public SignatureLevel[] getSignatureLevels() {
		return new SignatureLevel[] { SignatureLevel.JSON_NOT_ETSI, SignatureLevel.JAdES_BASELINE_B };
	}

	@Override
	public void checkSignaturePolicy(SignaturePolicyProvider signaturePolicyDetector) {
		// TODO Auto-generated method stub

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
		final CertificateToken certificateToken = getSigningCertificateToken();
		final TokenIdentifier identifier = certificateToken == null ? null : certificateToken.getDSSId();
		return SignatureIdentifier.buildSignatureIdentifier(getSigningTime(), identifier, jws.getEncodedHeader());
	}

	public DSSDocument getOriginalDocument() {
		return new InMemoryDocument(jws.getUnverifiedPayloadBytes());
	}

}
