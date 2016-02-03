package eu.europa.esig.dss.web.model;

import java.util.Date;
import java.util.List;

import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.NotNull;

import org.springframework.web.multipart.MultipartFile;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;

public class NexuSignatureDocumentForm {

	// @AssertTrue(message = "{error.nexu.not.found}")
	private boolean nexuDetected;

	private Date signingDate;

	private boolean signWithExpiredCertificate;

	private MultipartFile documentToSign;

	@NotNull(message = "{error.signature.form.mandatory}")
	private SignatureForm signatureForm;

	private SignatureForm asicUnderlyingForm;

	@NotNull(message = "{error.signature.packaging.mandatory}")
	private SignaturePackaging signaturePackaging;

	@NotNull(message = "{error.signature.level.mandatory}")
	private SignatureLevel signatureLevel;

	@NotNull(message = "{error.digest.algo.mandatory}")
	private DigestAlgorithm digestAlgorithm;

	private String policyOid;

	private DigestAlgorithm policyDigestAlgorithm;

	private String policyBase64HashValue;

	private String base64Certificate;

	private List<String> base64CertificateChain;

	private EncryptionAlgorithm encryptionAlgorithm;

	private String base64SignatureValue;

	public boolean isNexuDetected() {
		return nexuDetected;
	}

	public void setNexuDetected(boolean nexuDetected) {
		this.nexuDetected = nexuDetected;
	}

	public Date getSigningDate() {
		return signingDate;
	}

	public void setSigningDate(Date signingDate) {
		this.signingDate = signingDate;
	}

	public boolean isSignWithExpiredCertificate() {
		return signWithExpiredCertificate;
	}

	public void setSignWithExpiredCertificate(boolean signWithExpiredCertificate) {
		this.signWithExpiredCertificate = signWithExpiredCertificate;
	}

	public MultipartFile getDocumentToSign() {
		return documentToSign;
	}

	public void setDocumentToSign(MultipartFile documentToSign) {
		this.documentToSign = documentToSign;
	}

	public SignatureForm getSignatureForm() {
		return signatureForm;
	}

	public void setSignatureForm(SignatureForm signatureForm) {
		this.signatureForm = signatureForm;
	}

	public SignatureForm getAsicUnderlyingForm() {
		return asicUnderlyingForm;
	}

	public void setAsicUnderlyingForm(SignatureForm asicUnderlyingForm) {
		this.asicUnderlyingForm = asicUnderlyingForm;
	}

	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging;
	}

	public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
		this.signaturePackaging = signaturePackaging;
	}

	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	public void setSignatureLevel(SignatureLevel signatureLevel) {
		this.signatureLevel = signatureLevel;
	}

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	public String getBase64Certificate() {
		return base64Certificate;
	}

	public void setBase64Certificate(String base64Certificate) {
		this.base64Certificate = base64Certificate;
	}

	public List<String> getBase64CertificateChain() {
		return base64CertificateChain;
	}

	public void setBase64CertificateChain(List<String> base64CertificateChain) {
		this.base64CertificateChain = base64CertificateChain;
	}

	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
		this.encryptionAlgorithm = encryptionAlgorithm;
	}

	public String getBase64SignatureValue() {
		return base64SignatureValue;
	}

	public void setBase64SignatureValue(String base64SignatureValue) {
		this.base64SignatureValue = base64SignatureValue;
	}

	public String getPolicyOid() {
		return policyOid;
	}

	public void setPolicyOid(String policyOid) {
		this.policyOid = policyOid;
	}

	public DigestAlgorithm getPolicyDigestAlgorithm() {
		return policyDigestAlgorithm;
	}

	public void setPolicyDigestAlgorithm(DigestAlgorithm policyDigestAlgorithm) {
		this.policyDigestAlgorithm = policyDigestAlgorithm;
	}

	public String getPolicyBase64HashValue() {
		return policyBase64HashValue;
	}

	public void setPolicyBase64HashValue(String policyBase64HashValue) {
		this.policyBase64HashValue = policyBase64HashValue;
	}

	@AssertTrue(message = "{error.to.sign.file.mandatory}")
	public boolean isDocumentToSign() {
		return (documentToSign != null) && (!documentToSign.isEmpty());
	}

	@AssertTrue(message = "{error.signature.underlying.form.mandatory}")
	public boolean isAsicUnderlyingFormValid() {
		if (SignatureForm.ASiC_S.equals(signatureForm) || SignatureForm.ASiC_E.equals(signatureForm)) {
			return SignatureForm.CAdES.equals(asicUnderlyingForm) || SignatureForm.XAdES.equals(asicUnderlyingForm);
		} else {
			return true;
		}
	}
}
