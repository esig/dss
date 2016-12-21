package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.SignatureValue;

public abstract class AbstractSignDocumentDTO {

	private RemoteSignatureParameters parameters;
	private SignatureValue signatureValue;

	public AbstractSignDocumentDTO(RemoteSignatureParameters parameters, SignatureValue signatureValue) {
		super();
		this.parameters = parameters;
		this.signatureValue = signatureValue;
	}

	public RemoteSignatureParameters getParameters() {
		return parameters;
	}

	public void setParameters(RemoteSignatureParameters parameters) {
		this.parameters = parameters;
	}

	public SignatureValue getSignatureValue() {
		return signatureValue;
	}

	public void setSignatureValue(SignatureValue signatureValue) {
		this.signatureValue = signatureValue;
	}

}
