/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.encryption;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.crypto.prng.FixedSecureRandom;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
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
	 * The parameters to compute seed value from
	 */
	private PAdESCommonParameters parameters;
	
	/**
	 * The default constructor taking an object to compute seeds from
	 * Concatenates all attributes from PAdESCommonParameters to a BAOS
	 * 
	 * @param parameters {@link PAdESCommonParameters} to compute seed value from
	 */
	public DSSSecureRandomProvider(PAdESCommonParameters parameters) {
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
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			baos.write(parameters.getContentSize());
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			if (digestAlgorithm != null) {
				baos.write(digestAlgorithm.getName().getBytes());
			}
			String filter = parameters.getFilter();
			if (filter != null) {
				baos.write(filter.getBytes());
			}
			SignatureImageParameters imageParameters = parameters.getImageParameters();
			if (imageParameters != null) {
				baos.write(imageParameters.toString().getBytes());
			}
			String passwordProtection = parameters.getPasswordProtection();
			if (passwordProtection != null) {
				baos.write(passwordProtection.getBytes());
			}
			Date signingDate = parameters.getSigningDate();
			if (signingDate != null) {
				baos.write((int)signingDate.getTime());
			}
			String subFilter = parameters.getSubFilter();
			if (subFilter != null) {
				baos.write(subFilter.getBytes());
			}
			return baos.toByteArray();
			
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to build a seed value. Reason : %s", e.getMessage()), e);
		}
	}

}
