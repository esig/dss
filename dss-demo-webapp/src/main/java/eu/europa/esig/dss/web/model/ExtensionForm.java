package eu.europa.esig.dss.web.model;

import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.NotNull;

import org.springframework.web.multipart.MultipartFile;

import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;

public class ExtensionForm {

	private MultipartFile signedFile;

	private MultipartFile originalFile;

	@NotNull(message = "{error.signature.form.mandatory}")
	private SignatureForm signatureForm;

	private SignatureForm asicUnderlyingForm;

	@NotNull(message = "{error.signature.level.mandatory}")
	private SignatureLevel signatureLevel;

	public MultipartFile getSignedFile() {
		return signedFile;
	}

	public void setSignedFile(MultipartFile signedFile) {
		this.signedFile = signedFile;
	}

	public MultipartFile getOriginalFile() {
		return originalFile;
	}

	public void setOriginalFile(MultipartFile originalFile) {
		this.originalFile = originalFile;
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


	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	public void setSignatureLevel(SignatureLevel signatureLevel) {
		this.signatureLevel = signatureLevel;
	}

	@AssertTrue(message = "{error.signed.file.mandatory}")
	public boolean isSignedFile() {
		return (signedFile != null) && (!signedFile.isEmpty());
	}

	@AssertTrue(message = "{error.signature.underlying.form.mandatory}")
	public boolean isAsicUnderlyingFormValid(){
		if (SignatureForm.ASiC_S.equals(signatureForm) || SignatureForm.ASiC_E.equals(signatureForm)){
			return SignatureForm.CAdES.equals(asicUnderlyingForm) || SignatureForm.XAdES.equals(asicUnderlyingForm);
		} else{
			return true;
		}
	}
}
