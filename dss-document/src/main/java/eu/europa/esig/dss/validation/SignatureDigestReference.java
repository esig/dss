package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;

/**
 * A signature reference element references a specific electronic signature.
 * Contains Digest of a referenced signature
 */
public class SignatureDigestReference {
	
	private String canonicalizationMethod;
	private final Digest digest;
	
	public SignatureDigestReference(Digest digest) {
		this.digest = digest;
	}
	
	public SignatureDigestReference(String canonicalizationMethod, Digest digest) {
		this.canonicalizationMethod = canonicalizationMethod;
		this.digest = digest;
	}
	
	/**
	 * Returns canonicalization method used to calculate digest
	 * @return {@link String}
	 */
	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}
	
	/**
	 * Returns {@code DigestAlgorithm} used to calculate digest value
	 * @return {@link DigestAlgorithm}
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digest.getAlgorithm();
	}
	
	/**
	 * Returns calculated digest value
	 * @return byte array
	 */
	public byte[] getDigestValue() {
		return digest.getValue();
	}
	
}
