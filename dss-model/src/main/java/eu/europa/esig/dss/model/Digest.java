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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;

/**
 * Container for a Digest and his algorithm
 */
@SuppressWarnings("serial")
public final class Digest implements Serializable {

	/** The used DigestAlgorithm */
	private DigestAlgorithm algorithm;

	/** The digest value */
	private byte[] value;

	/**
	 * Empty constructor
	 */
	public Digest() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param algorithm {@link DigestAlgorithm} used algorithm
	 * @param value byte array digest
	 */
	public Digest(DigestAlgorithm algorithm, byte[] value) {
		this.algorithm = algorithm;
		this.value = value;
	}

	/**
	 * Gets the HEX (base16) encoded digest value String
	 *
	 * @return {@link String} HEX-encoded digest
	 */
	public String getHexValue() {
		String hex = new BigInteger(1, value).toString(16);
		if (hex.length() % 2 == 1) {
			hex = "0" + hex;
		}
		return hex.toUpperCase(Locale.ENGLISH);
	}

	/**
	 * Gets the DigestAlgorithm
	 *
	 * @return the algorithm
	 */
	public DigestAlgorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * Sets the DigestAlgorithm
	 *
	 * @param algorithm
	 *                  the algorithm to set
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
		Digest other = (Digest) obj;
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
		return ((algorithm == null) ? "?" : algorithm.getName()) + ":" + ((value == null) ? "?" : getHexValue());
	}
	
}
