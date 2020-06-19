package eu.europa.esig.dss.pdf.encryption;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.crypto.prng.FixedSecureRandom;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SerializableParameters;
import eu.europa.esig.dss.pades.PAdESCommonParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

/**
 * Default {@code SecureRandomProvider} used in DSS, 
 * returning org.bouncycastle.crypto.prng.FixedSecureRandom instance
 *
 */
public class DSSSecureRandomProvider implements SecureRandomProvider {
	
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
	 * Parameters to compute seed value from
	 */
	private SerializableParameters parameters;
	
	public DSSSecureRandomProvider(SerializableParameters parameters) {
		this.parameters = parameters;
	}

	/**
	 * A default constructor to instantiate a FixedSecureRandomProvider from parameters
	 * 
	 * @param parameters to be used for signature/timestamp creation/extenstion
	 */
	@Override
	public void setParameters(final SerializableParameters parameters) {
		this.parameters = parameters;
	}
	
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
	public SecureRandom getSecureRandom() {
		byte[] seed = buildSeed();
		byte[] value = DSSUtils.digest(digestAlgorithm, seed);
		while (value.length < binaryLength) {
			value = DSSUtils.concatenate(value, value);
		}
		value = Utils.subarray(value, 0, binaryLength);
		return new FixedSecureRandom(value);
	}
	
	private byte[] buildSeed() {
		if (parameters == null) {
			throw new DSSException("Parameters must be defined! Unable to use DSSFixedSecureRandomProvider.");
		}
		if (parameters instanceof PAdESCommonParameters) {
			PAdESCommonParameters commonParameters = (PAdESCommonParameters) parameters;
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				baos.write(commonParameters.getContentSize());
				DigestAlgorithm digestAlgorithm = commonParameters.getDigestAlgorithm();
				if (digestAlgorithm != null) {
					baos.write(digestAlgorithm.getName().getBytes());
				}
				String fieldId = commonParameters.getFieldId();
				if (fieldId != null) {
					baos.write(fieldId.getBytes());
				}
				String filter = commonParameters.getFilter();
				if (filter != null) {
					baos.write(filter.getBytes());
				}
				SignatureImageParameters imageParameters = commonParameters.getImageParameters();
				if (imageParameters != null) {
					baos.write(imageParameters.toString().getBytes());
				}
				String passwordProtection = commonParameters.getPasswordProtection();
				if (passwordProtection != null) {
					baos.write(passwordProtection.getBytes());
				}
				Date signingDate = commonParameters.getSigningDate();
				if (signingDate != null) {
					baos.write((int)signingDate.getTime());
				}
				String subFilter = commonParameters.getSubFilter();
				if (subFilter != null) {
					baos.write(subFilter.getBytes());
				}
				return baos.toByteArray();
				
			} catch (IOException e) {
				throw new DSSException(String.format("Unable to build a seed value. Reason : %s", e.getMessage()), e);
			}
			
		} else {
			return parameters.toString().getBytes();
		}
		
	}

}
