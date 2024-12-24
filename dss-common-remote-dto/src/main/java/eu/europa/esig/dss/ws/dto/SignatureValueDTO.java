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

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Base64;

/**
 * Represents a SignatureValue DTO
 */
@SuppressWarnings("serial")
public class SignatureValueDTO implements Serializable {

	/**
	 * The used SignatureAlgorithm
	 */
	private SignatureAlgorithm algorithm;

	/**
	 * The SignatureValue binaries
	 */
	private byte[] value;

	/**
	 * Empty constructor
	 */
	public SignatureValueDTO() {
	}

	/**
	 * The default constructor
	 *
	 * @param algorithm {@link SignatureAlgorithm} used to compute the SignatureValue
	 * @param value the SignatureValue binaries
	 */
	public SignatureValueDTO(SignatureAlgorithm algorithm, byte[] value) {
		this.algorithm = algorithm;
		this.value = value;
	}

	/**
	 * Gets the used {@link SignatureAlgorithm}
	 *
	 * @return {@link SignatureAlgorithm}
	 */
	public SignatureAlgorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * Sets the used {@link SignatureAlgorithm}
	 *
	 * @param algorithm {@link SignatureAlgorithm}
	 */
	public void setAlgorithm(SignatureAlgorithm algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * Gets the SignatureValue binaries
	 *
	 * @return the SignatureValue binaries
	 */
	public byte[] getValue() {
		return value;
	}

	/**
	 * Sets the SignatureValue binaries
	 *
	 * @param value the SignatureValue binaries
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
		SignatureValueDTO other = (SignatureValueDTO) obj;
		if (algorithm != other.algorithm) {
			return false;
		}
		return Arrays.equals(value, other.value);
	}

	@Override
	public String toString() {
		return "SignatureValue [algorithm=" + algorithm + ", value=" + ((value != null) ? Base64.getEncoder().encodeToString(value) : null) + "]";
	}

}
