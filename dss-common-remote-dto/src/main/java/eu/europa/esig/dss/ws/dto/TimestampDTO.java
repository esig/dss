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
package eu.europa.esig.dss.ws.dto;

import eu.europa.esig.dss.enumerations.TimestampType;

import java.io.Serializable;
import java.util.List;

/**
 * DTO to transfer a TimestampToken over REST/SOAP webServices
 */
public class TimestampDTO implements Serializable {

	private static final long serialVersionUID = -8661917001841886938L;

	/** The timestamp token's DER-encoded binaries */
	private byte[] binaries;

	/** The canonicalization method (for XAdES/JAdES formats) */
	private String canonicalizationMethod;

	/** The type of the timestamp */
	private TimestampType type;

	/** Defines signed references for a XAdES IndividualDataObjectsTimeStamp */
	private List<TimestampIncludeDTO> includes;

	/**
	 * Empty constructor
	 */
	public TimestampDTO() {
	}

	/**
	 * Default constructor
	 *
	 * @param binaries DER-encoded binaries of the timestamp
	 * @param type {@link TimestampType} of the timestamp
	 */
	public TimestampDTO(final byte[] binaries, final TimestampType type) {
		this.binaries = binaries;
		this.type = type;
	}

	/**
	 * Gets DER-encoded binaries of the timestamp
	 *
	 * @return DER-encoded binaries
	 */
	public byte[] getBinaries() {
		return binaries;
	}

	/**
	 * Sets DER-encoded binaries of the timestamp
	 *
	 * @param binaries DER-encoded binaries
	 */
	public void setBinaries(byte[] binaries) {
		this.binaries = binaries;
	}

	/**
	 * Gets the canonicalization method (for XAdES/JAdES)
	 *
	 * @return {@link String} canonicalization method URI
	 */
	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	/**
	 * Sets the canonicalization method (for XAdES/JAdES)
	 *
	 * @param canonicalizationMethod {@link String} canonicalization method URI
	 */
	public void setCanonicalizationMethod(String canonicalizationMethod) {
		this.canonicalizationMethod = canonicalizationMethod;
	}

	/**
	 * Gets type of the timestamp
	 *
	 * @return {@link TimestampType}
	 */
	public TimestampType getType() {
		return type;
	}

	/**
	 * Sets type of the timestamp
	 *
	 * @param type {@link TimestampType}
	 */
	public void setType(TimestampType type) {
		this.type = type;
	}

	/**
	 * Gets covered references for a XAdES IndividualDataObjectsTimeStamp
	 *
	 * @return a list of {@link TimestampIncludeDTO}
	 */
	public List<TimestampIncludeDTO> getIncludes() {
		return includes;
	}

	/**
	 * Sets covered references for a XAdES IndividualDataObjectsTimeStamp
	 *
	 * @param includes a list of {@link TimestampIncludeDTO}
	 */
	public void setIncludes(List<TimestampIncludeDTO> includes) {
		this.includes = includes;
	}
	
}
