/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.encryption;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.PAdESCommonParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.crypto.prng.FixedSecureRandom;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Objects;

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
	 * The parameters to compute seed value from
	 */
	private PAdESCommonParameters parameters;

	/**
	 * The image parameters to compute seed value from
	 */
	private SignatureImageParameters imageParameters;
	
	/**
	 * The default constructor taking an object to compute seeds from.
	 * Concatenates all attributes from PAdESCommonParameters to a BAOS.
	 * 
	 * @param parameters {@link PAdESCommonParameters} to compute seed value from
	 */
	public DSSSecureRandomProvider(PAdESCommonParameters parameters) {
		Objects.requireNonNull(parameters, "Parameters must be defined! Unable to instantiate DSSSecureRandomProvider.");
		this.parameters = parameters;
	}

	/**
	 * Constructor to instantiate DSSSecureRandomProvider from image parameters.
	 * Concatenates all attributes from SignatureImageParameters to a BAOS.
	 *
	 * @param imageParameters {@link SignatureImageParameters} to compute seed value from
	 */
	public DSSSecureRandomProvider(SignatureImageParameters imageParameters) {
		Objects.requireNonNull(imageParameters, "Parameters must be defined! Unable to instantiate DSSSecureRandomProvider.");
		this.imageParameters = imageParameters;
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
			throw new IllegalArgumentException("The binaryLength cannot be less then 16 bytes!");
		}
		this.binaryLength = binaryLength;
	}

	@Override
	public SecureRandom getSecureRandom() {
		byte[] seed = buildSeed();
		byte[] value = DSSUtils.digest(digestAlgorithm, seed);
		while (value.length < binaryLength) {
			value = Utils.concat(value, value);
		}
		value = Utils.subarray(value, 0, binaryLength);
		return new FixedSecureRandom(value);
	}
	
	private byte[] buildSeed() {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			if (parameters != null) {
				baos.write(parameters.getContentSize());
				DigestAlgorithm parametersDigestAlgorithm = parameters.getDigestAlgorithm();
				if (parametersDigestAlgorithm != null) {
					baos.write(parametersDigestAlgorithm.getName().getBytes());
				}
				String filter = parameters.getFilter();
				if (filter != null) {
					baos.write(filter.getBytes());
				}
				SignatureImageParameters parametersImageParameters = parameters.getImageParameters();
				if (parametersImageParameters != null) {
					baos.write(parametersImageParameters.toString().getBytes());
				}
				Date signingDate = parameters.getSigningDate();
				if (signingDate != null) {
					baos.write((int)signingDate.getTime());
				}
				String subFilter = parameters.getSubFilter();
				if (subFilter != null) {
					baos.write(subFilter.getBytes());
				}

			} else if (imageParameters != null) {
				baos.write(imageParameters.toString().getBytes());
			}
			return baos.toByteArray();
			
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to build a seed value. Reason : %s", e.getMessage()), e);
		}
	}

}
