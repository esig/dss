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
import java.util.List;

/**
 * Represents a VRI dictionary
 */
public class PdfVRIDict extends AbstractPdfDssDict {

	private static final long serialVersionUID = -1545254066906625419L;
	
	/** The VRI dictionary key (SHA-1 value of a signature) */
	private final String name;

	/**
	 * Default constructor
	 *
	 * @param name {@link String} VRI dictionary key
	 * @param vriDict {@link PdfDict} the dictionary
	 */
	public PdfVRIDict(String name, PdfDict vriDict) {
		super(vriDict);
		this.name = name;
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

	@Override
	public List<PdfVRIDict> getVRIs() {
		// not applicable for VRI
		return Collections.emptyList();
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
		PdfVRIDict other = (PdfVRIDict) obj;
		if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}

}
