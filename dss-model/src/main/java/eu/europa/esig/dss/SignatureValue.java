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
package eu.europa.esig.dss;

import java.io.Serializable;
import java.util.Arrays;

@SuppressWarnings("serial")
public final class SignatureValue implements Serializable {

	private SignatureAlgorithm algorithm;

	private byte[] value;

	public SignatureValue() {
	}

	public SignatureValue(SignatureAlgorithm algorithm, byte[] value) {
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
		SignatureValue other = (SignatureValue) obj;
		if (algorithm != other.algorithm) {
			return false;
		}
		if (!Arrays.equals(value, other.value)) {
			return false;
		}
		return true;
	}

}
