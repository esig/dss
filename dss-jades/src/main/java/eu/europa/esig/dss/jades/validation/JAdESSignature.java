package eu.europa.esig.dss.jades.validation;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.jose4j.json.internal.json_simple.JSONObject;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.spi.x509.CertificatePool;
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

	private final CustomJsonWebSignature jws;

	public JAdESSignature(CustomJsonWebSignature jws, CertificatePool certPool) {
		super(certPool);
		this.jws = jws;
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
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SignatureCertificateSource getCertificateSource() {
		// TODO Auto-generated method stub
		return null;
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
		// TODO Auto-generated method stub
		return null;
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
			//	result.addIdentifier(identifier);

			return result;
		}
		return null;
	}

	@Override
	public String getContentType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getMimeType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getContentIdentifier() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getContentHints() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<SignerRole> getClaimedSignerRoles() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<SignerRole> getCertifiedSignerRoles() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<AdvancedSignature> getCounterSignatures() {
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getCertificateRefs() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getDAIdentifier() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isDataForSignatureLevelPresent(SignatureLevel signatureLevel) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public SignatureLevel[] getSignatureLevels() {
		// TODO Auto-generated method stub
		return null;
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
