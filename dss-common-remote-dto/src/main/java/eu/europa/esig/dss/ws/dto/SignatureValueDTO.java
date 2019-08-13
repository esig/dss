package eu.europa.esig.dss.ws.dto;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Base64;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

@SuppressWarnings("serial")
public class SignatureValueDTO implements Serializable {

	private SignatureAlgorithm algorithm;

	private byte[] value;

	public SignatureValueDTO() {
	}

	public SignatureValueDTO(SignatureAlgorithm algorithm, byte[] value) {
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((algorithm == null) ? 0 : algorithm.hashCode());
		result = (prime * result) + Arrays.hashCode(value);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SignatureValueDTO other = (SignatureValueDTO) obj;
		if (algorithm != other.algorithm) {
			return false;
		}
		if (!Arrays.equals(value, other.value)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "SignatureValue [algorithm=" + algorithm + ", value=" + ((value != null) ? Base64.getEncoder().encodeToString(value) : null) + "]";
	}

}
