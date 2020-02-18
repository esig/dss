package eu.europa.esig.dss.jades.validation;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.jwx.HeaderParameterNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CandidatesForSigningCertificate;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.CommitmentType;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.SignatureCRLSource;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
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
		return new JAdESCertificateSource(jws, certPool);
	}

	@Override
	public SignatureCRLSource getCRLSource() {
		return new JAdESCRLSource();
	}

	@Override
	public SignatureOCSPSource getOCSPSource() {
		return new JAdESOCSPSource();
	}

	@Override
	public SignatureTimestampSource getTimestampSource() {
		return new JAdESTimestampSource(this, certPool);
	}

	@Override
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void checkSignatureIntegrity() {
		// TODO Auto-generated method stub

	}

	@Override
	public void checkSigningCertificate() {
		// TODO Auto-generated method stub

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
			CommitmentType result = new CommitmentType();

			// TODO missing OID definition
			// result.addIdentifier(identifier);

			return result;
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
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected SignatureIdentifier buildSignatureIdentifier() {
		// TODO Auto-generated method stub
		return null;
	}

}
