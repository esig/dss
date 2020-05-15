package eu.europa.esig.dss.pdf;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Objects;

import org.bouncycastle.crypto.prng.FixedSecureRandom;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SerializableParameters;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

/**
 * Default implementation of SecureRandomProvider
 * Returns BouncyCastle FixedSecureRandom instance based on SHA512 of serialized bytes obtained from the given parameters
 *
 */
public class FixedSecureRandomProvider implements SecureRandomProvider {
	
	/**
	 * DigestAlgorithm used for random string generation
	 */
	private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA512;

	/** 
	 * Amount of bytes to be initialized in a FixedSecureRandom
	 * Each AES Initialization Vector call takes 16 bytes
	 * NOTE: if document contains a lot of objects to be encrypted, the value may need to be increased
	 * Default: 512 bytes
	 */
	private int binaryLength = 512;
	
	/**
	 * Allows to set a DigestAlgorithm that will be applied on serialized parameters
	 * 
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 */
	public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * Sets the amount of bytes to be computed for FixedSecureRandom
	 * 16 bytes is required per one AES Vector initialization
	 * 
	 * @param binaryLength number of bytes
	 */
	public void setBinaryLength(int binaryLength) {
		if (binaryLength < 16) {
			throw new DSSException("The binaryLength cannot be less then 16 bytes!");
		}
		this.binaryLength = binaryLength;
	}

	@Override
	public SecureRandom getSecureRandom(SerializableParameters parameters) throws IOException {
		byte[] serializedBytes = Utils.serialize(parameters);
		byte[] value = DSSUtils.digest(digestAlgorithm, serializedBytes);
		while (value.length < binaryLength) {
			value = DSSUtils.concatenate(value, value);
		}
		value = Utils.subarray(value, 0, binaryLength);
		return new FixedSecureRandom(value);
	}

}
