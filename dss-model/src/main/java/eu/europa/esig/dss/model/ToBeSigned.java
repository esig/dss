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

import java.io.Serializable;
import java.util.Arrays;

/**
 * Represents the ToBeSigned data
 */
@SuppressWarnings("serial")
public class ToBeSigned implements Serializable{

	/** The binaries to be signed */
	private byte[] bytes;

	/**
	 * Empty constructor
	 */
	public ToBeSigned() {
	}

	/**
	 * The default constructor
	 *
	 * @param bytes byte array to be signed
	 */
	public ToBeSigned(byte[] bytes) {
		this.bytes = bytes;
	}

	/**
	 * Gets bytes to be signed
	 *
	 * @return byte array
	 */
	public byte[] getBytes() {
		return bytes;
	}

	/**
	 * Sets bytes to be signed
	 *
	 * @param bytes byte array
	 */
	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + Arrays.hashCode(bytes);
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
		ToBeSigned other = (ToBeSigned) obj;
		if (!Arrays.equals(bytes, other.bytes)) {
			return false;
		}
		return true;
	}

}
