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
package eu.europa.esig.dss.pdf;

import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Represents a VRI dictionary
 */
public class PdfVriDict extends AbstractPdfDssDict {

	private static final long serialVersionUID = -1545254066906625419L;
	
	/** The VRI dictionary key (SHA-1 value of a signature) */
	private final String name;

	/** Number of the VRI dictionary */
	private final Integer number;

	/** Represents a 'TU' time value */
	private final Date tuTime;

	/** Represents a 'TS' timestamp binary value */
	private final byte[] tsStream;

	/**
	 * Default constructor
	 *
	 * @param name {@link String} VRI dictionary key
	 * @param vriDict {@link PdfDict} the dictionary
	 * @deprecated since DSS 5.13. Please use {@code PdfVriDict(String name, Integer number, PdfDict vriDict)}.
	 */
	@Deprecated
	public PdfVriDict(String name, PdfDict vriDict) {
		this(name, null, vriDict);
	}

	/**
	 * Constructor with information about the VRI dictionary
	 *
	 * @param name {@link String} VRI dictionary key
	 * @param number {@link Integer} dictionary number
	 * @param vriDict {@link PdfDict} the dictionary
	 */
	public PdfVriDict(String name, Integer number, PdfDict vriDict) {
		super(vriDict);
		this.name = name;
		this.number = number;
		this.tuTime = DSSDictionaryExtractionUtils.getDictionaryCreationTime(vriDict);
		this.tsStream = DSSDictionaryExtractionUtils.getTimestampBinaries(vriDict);
	}
	
	@Override
	protected String getDictionaryName() {
		return PAdESConstants.VRI_DICTIONARY_NAME;
	}
	
	@Override
	protected String getCertArrayDictionaryName() {
		return PAdESConstants.CERT_ARRAY_NAME_VRI;
	}
	
	@Override
	protected String getCRLArrayDictionaryName() {
		return PAdESConstants.CRL_ARRAY_NAME_VRI;
	}
	
	@Override
	protected String getOCSPArrayDictionaryName() {
		return PAdESConstants.OCSP_ARRAY_NAME_VRI;
	}

	/**
	 * Returns key of the VRI dictionary
	 *
	 * @return {@link String}
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns dictionary number of the current VRI dictionary
	 *
	 * @return {@link Integer}
	 */
	public Integer getNumber() {
		return number;
	}

	@Override
	public List<PdfVriDict> getVRIs() {
		// not applicable for VRI
		return Collections.emptyList();
	}

	/**
	 * Returns 'TU' time
	 *
	 * @return {@link Date} when 'TU' value is present, NULL otherwise
	 */
	public Date getTUTime() {
		return tuTime;
	}

	/**
	 * Returns 'TS' stream value
	 *
	 * @return byte array representing a timestamp when present, NULL otherwise
	 */
	public byte[] getTSStream() {
		return tsStream;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + name.hashCode();
		return result;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		PdfVriDict other = (PdfVriDict) obj;
		if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}

}
