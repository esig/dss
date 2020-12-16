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
package eu.europa.esig.dss.ws.timestamp.dto;

import java.io.Serializable;
import java.util.Arrays;

/**
 * The DTO representing a response of a timestamp service
 */
@SuppressWarnings("serial")
public class TimestampResponseDTO implements Serializable {

	/** The timestamp binaries */
    private byte[] binaries;

	/**
	 * Default constructor
	 */
	public TimestampResponseDTO() {
    }

	/**
	 * Gets binaries of the timestamp's response
	 *
	 * @return binaries
	 */
	public byte[] getBinaries() {
        return binaries;
    }

	/**
	 * Sets binaries of the timestamp's response
	 *
	 * @param binaries byte array
	 */
	public void setBinaries(byte[] binaries) {
        this.binaries = binaries;
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(binaries);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		TimestampResponseDTO trDTO = (TimestampResponseDTO) obj;
		if (!Arrays.equals(binaries, trDTO.binaries))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "TimestampResponseDTO [bytes=" + Arrays.toString(binaries) + "]";
	}

}
