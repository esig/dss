package eu.europa.esig.dss.web.model;

import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.NotNull;

import org.springframework.web.multipart.MultipartFile;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;

public class ExtensionForm {

	private MultipartFile signedFile;

	private MultipartFile originalFile;

	private ASiCContainerType containerType;

	@NotNull(message = "{error.signature.form.mandatory}")
	private SignatureForm signatureForm;

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

	public ASiCContainerType getContainerType() {
		return containerType;
	}

	public void setContainerType(ASiCContainerType containerType) {
		this.containerType = containerType;
	}

	public SignatureForm getSignatureForm() {
		return signatureForm;
	}

	public void setSignatureForm(SignatureForm signatureForm) {
		this.signatureForm = signatureForm;
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

}
