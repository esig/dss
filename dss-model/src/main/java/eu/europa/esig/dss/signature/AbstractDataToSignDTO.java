package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.RemoteSignatureParameters;

public abstract class AbstractDataToSignDTO {

	private RemoteSignatureParameters parameters;

	protected AbstractDataToSignDTO(RemoteSignatureParameters parameters) {
		super();
		this.parameters = parameters;
	}

	public RemoteSignatureParameters getParameters() {
		return parameters;
	}

	public void setParameters(RemoteSignatureParameters parameters) {
		this.parameters = parameters;
	}

}
