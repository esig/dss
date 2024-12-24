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
package eu.europa.esig.dss.ws.dto;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;

/**
 * Represent the Digest DTO
 */
@SuppressWarnings("serial")
public class DigestDTO implements Serializable {

	/** The used DigestAlgorithm */
	private DigestAlgorithm algorithm;

	/** The digest's value */
	private byte[] value;

	/**
	 * The empty constructor
	 */
	public DigestDTO() {
	}

	/**
	 * The default constructor
	 *
	 * @param algorithm {@link DigestAlgorithm} used for the digest calculation
	 * @param value of the digest
	 */
	public DigestDTO(DigestAlgorithm algorithm, byte[] value) {
		this.algorithm = algorithm;
		this.value = value;
	}

	/**
	 * Gets the {@link DigestAlgorithm}
	 *
	 * @return the algorithm
	 */
	public DigestAlgorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * Sets the {@link DigestAlgorithm}
	 *
	 * @param algorithm
	 *                 {@link DigestAlgorithm} the algorithm to set
	 */
	public void setAlgorithm(DigestAlgorithm algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * Gets the digest value
	 *
	 * @return the value
	 */
	public byte[] getValue() {
		return value;
	}

	/**
	 * Sets the digest value
	 *
	 * @param value
	 *              the value to set
	 */
	public void setValue(byte[] value) {
		this.value = value;
	}

	/**
	 * Returns a hex-encoded digest value
	 *
	 * @return {@link String} hex-encoded
	 */
	protected String hexValue() {
		String hex = new BigInteger(1, value).toString(16);
		if (hex.length() % 2 == 1) {
			hex = "0" + hex;
		}
		return hex.toUpperCase(Locale.ENGLISH);
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
		return Arrays.equals(value, other.value);
	}
	
	@Override
	public String toString() {
		return algorithm.getName() + ":" + hexValue();
	}
	
}