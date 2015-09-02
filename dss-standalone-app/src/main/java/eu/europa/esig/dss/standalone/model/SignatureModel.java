package eu.europa.esig.dss.standalone.model;

import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureTokenType;

public class SignatureModel {

	private ObjectProperty<SignatureForm> signatureForm = new SimpleObjectProperty<SignatureForm>();
	private ObjectProperty<SignatureForm> asicUnderlyingForm = new SimpleObjectProperty<SignatureForm>();
	private ObjectProperty<SignaturePackaging> signaturePackaging = new SimpleObjectProperty<SignaturePackaging>();
	private ObjectProperty<SignatureLevel> signatureLevel = new SimpleObjectProperty<SignatureLevel>();
	private ObjectProperty<DigestAlgorithm> digestAlgorithm = new SimpleObjectProperty<DigestAlgorithm>();
	private ObjectProperty<SignatureTokenType> tokenType = new SimpleObjectProperty<SignatureTokenType>();

	public SignatureForm getSignatureForm() {
		return signatureForm.get();
	}

	public void setSignatureForm(SignatureForm signatureForm) {
		this.signatureForm.set(signatureForm);
	}

	public ObjectProperty<SignatureForm> signatureFormProperty(){
		return signatureForm;
	}

	public SignatureForm getAsicUnderlyingForm() {
		return asicUnderlyingForm.get();
	}

	public void setAsicUnderlyingForm(SignatureForm asicUnderlyingForm) {
		this.asicUnderlyingForm.set(asicUnderlyingForm);
	}

	public ObjectProperty<SignatureForm> asicUnderlyingFormProperty(){
		return asicUnderlyingForm;
	}

	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging.get();
	}

	public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
		this.signaturePackaging.set(signaturePackaging);
	}

	public ObjectProperty<SignaturePackaging> signaturePackagingProperty(){
		return signaturePackaging;
	}

	public SignatureLevel getSignatureLevel() {
		return signatureLevel.get();
	}

	public void setSignatureLevel(SignatureLevel signatureLevel) {
		this.signatureLevel.set(signatureLevel);
	}

	public ObjectProperty<SignatureLevel> signatureLevelProperty(){
		return signatureLevel;
	}

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm.get();
	}

	public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm.set(digestAlgorithm);
	}

	public ObjectProperty<DigestAlgorithm> digestAlgorithmProperty(){
		return digestAlgorithm;
	}

	public SignatureTokenType getTokenType() {
		return tokenType.get();
	}

	public void setTokenType(SignatureTokenType tokenType) {
		this.tokenType.set(tokenType);
	}

	public ObjectProperty<SignatureTokenType> tokenTypeProperty(){
		return tokenType;
	}

}
