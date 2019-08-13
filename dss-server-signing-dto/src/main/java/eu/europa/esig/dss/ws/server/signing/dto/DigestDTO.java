package eu.europa.esig.dss.ws.server.signing.dto;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

@SuppressWarnings("serial")
public class DigestDTO implements Serializable {

	private DigestAlgorithm algorithm;

	private byte[] value;

	public DigestDTO() {
	}

	public DigestDTO(DigestAlgorithm algorithm, byte[] value) {
		this.algorithm = algorithm;
		this.value = value;
	}

	public String getHexValue() {
		String hex = new BigInteger(1, value).toString(16);
		if (hex.length() % 2 == 1) {
			hex = "0" + hex;
		}
		return hex.toUpperCase(Locale.ENGLISH);
	}

	/**
	 * @return the algorithm
	 */
	public DigestAlgorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * @param algorithm
	 *                  the algorithm to set
	 */
	public void setAlgorithm(DigestAlgorithm algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * @return the value
	 */
	public byte[] getValue() {
		return value;
	}

	/**
	 * @param value
	 *              the value to set
	 */
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
		DigestDTO other = (DigestDTO) obj;
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
		return algorithm.getName() + ":" + getHexValue();
	}
	
}