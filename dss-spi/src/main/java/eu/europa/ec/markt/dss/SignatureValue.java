package eu.europa.ec.markt.dss;

import java.io.Serializable;

@SuppressWarnings("serial")
public final class SignatureValue implements Serializable {

	private SignatureAlgorithm algorithm;
	
	private byte[] value;

	public SignatureValue() {
	}

	public SignatureValue(SignatureAlgorithm algorithm, byte[] value) {
		this.algorithm = algorithm;
		this.value = value;
	}

	public SignatureAlgorithm getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(SignatureAlgorithm algorithm) {
		this.algorithm = algorithm;
	}

	public byte[] getValue() {
		return value;
	}

	public void setValue(byte[] value) {
		this.value = value;
	}
	
}
