package eu.europa.esig.dss.standalone.model;

import java.io.File;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureTokenType;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

public class SignatureModel {

	private ObjectProperty<File> fileToSign = new SimpleObjectProperty<File>();
	private ObjectProperty<ASiCContainerType> asicContainerType = new SimpleObjectProperty<ASiCContainerType>();
	private ObjectProperty<SignatureForm> signatureForm = new SimpleObjectProperty<SignatureForm>();
	private ObjectProperty<SignaturePackaging> signaturePackaging = new SimpleObjectProperty<SignaturePackaging>();
	private ObjectProperty<SignatureLevel> signatureLevel = new SimpleObjectProperty<SignatureLevel>();
	private ObjectProperty<DigestAlgorithm> digestAlgorithm = new SimpleObjectProperty<DigestAlgorithm>();
	private ObjectProperty<SignatureTokenType> tokenType = new SimpleObjectProperty<SignatureTokenType>();

	private ObjectProperty<File> pkcsFile = new SimpleObjectProperty<File>();
	private StringProperty password = new SimpleStringProperty();

	public File getFileToSign() {
		return fileToSign.get();
	}

	public void setFileToSign(File fileToSign) {
		this.fileToSign.set(fileToSign);
	}

	public ObjectProperty<File> fileToSignProperty() {
		return fileToSign;
	}

	public SignatureForm getSignatureForm() {
		return signatureForm.get();
	}

	public void setSignatureForm(SignatureForm signatureForm) {
		this.signatureForm.set(signatureForm);
	}

	public ObjectProperty<SignatureForm> signatureFormProperty() {
		return signatureForm;
	}

	public ASiCContainerType getAsicContainerType() {
		return asicContainerType.get();
	}

	public void setAsicContainerType(ASiCContainerType asicContainerType) {
		this.asicContainerType.set(asicContainerType);
	}

	public ObjectProperty<ASiCContainerType> asicContainerTypeProperty() {
		return asicContainerType;
	}

	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging.get();
	}

	public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
		this.signaturePackaging.set(signaturePackaging);
	}

	public ObjectProperty<SignaturePackaging> signaturePackagingProperty() {
		return signaturePackaging;
	}

	public SignatureLevel getSignatureLevel() {
		return signatureLevel.get();
	}

	public void setSignatureLevel(SignatureLevel signatureLevel) {
		this.signatureLevel.set(signatureLevel);
	}

	public ObjectProperty<SignatureLevel> signatureLevelProperty() {
		return signatureLevel;
	}

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm.get();
	}

	public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm.set(digestAlgorithm);
	}

	public ObjectProperty<DigestAlgorithm> digestAlgorithmProperty() {
		return digestAlgorithm;
	}

	public SignatureTokenType getTokenType() {
		return tokenType.get();
	}

	public void setTokenType(SignatureTokenType tokenType) {
		this.tokenType.set(tokenType);
	}

	public ObjectProperty<SignatureTokenType> tokenTypeProperty() {
		return tokenType;
	}

	public String getPassword() {
		return password.get();
	}

	public void setPassword(String password) {
		this.password.set(password);
	}

	public StringProperty passwordProperty() {
		return password;
	}

	public File getPkcsFile() {
		return pkcsFile.get();
	}

	public void setPkcsFile(File pkcsFile) {
		this.pkcsFile.set(pkcsFile);
	}

	public ObjectProperty<File> pkcsFileProperty() {
		return pkcsFile;
	}

}
