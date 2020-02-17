package eu.europa.esig.dss.jades.validation;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
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

	protected JAdESSignature(CertificatePool certPool) {
		super(certPool);
	}

	@Override
	public SignatureForm getSignatureForm() {
		return SignatureForm.JAdES;
	}

	@Override
	public SignatureAlgorithm getSignatureAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public MaskGenerationFunction getMaskGenerationFunction() {
		// TODO Auto-generated method stub
		return null;
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
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SignatureOCSPSource getOCSPSource() {
		// TODO Auto-generated method stub
		return null;
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
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CommitmentType getCommitmentTypeIndication() {
		// TODO Auto-generated method stub
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
		// TODO Auto-generated method stub
		return null;
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
		// TODO Auto-generated method stub
		return null;
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
