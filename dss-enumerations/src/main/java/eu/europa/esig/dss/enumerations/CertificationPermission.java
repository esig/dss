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
package eu.europa.esig.dss.enumerations;

/**
 * This enumeration is used to set the allowed level of permission for PDF modifications.
 * 
 * Refers to ISO 32000 DocMDP chapter
 */
public enum CertificationPermission {

	/**
	 * No changes to the document are permitted; any change to the document shall invalidate the signature.
	 */
	NO_CHANGE_PERMITTED(1),

	/**
	 * Permitted changes shall be filling in forms, instantiating page templates, and signing; other changes shall
	 * invalidate the signature.
	 */
	MINIMAL_CHANGES_PERMITTED(2),

	/**
	 * Permitted changes are the same as for 2, as well as annotation creation, deletion, and modification; other
	 * changes shall invalidate the signature.
	 */
	CHANGES_PERMITTED(3);

	/** The code of the DocMDP enumeration */
	private final int code;

	/**
	 * Default constructor
	 *
	 * @param code value
	 */
	CertificationPermission(int code) {
		this.code = code;
	}

	/**
	 * Gets value of /DocMDP dictionary
	 *
	 * @return code
	 */
	public int getCode() {
		return code;
	}

	/**
	 * Returns a CertificationPermission corresponding to the given code value
	 *
	 * @param code value
	 * @return {@link CertificationPermission}
	 */
	public static CertificationPermission fromCode(int code) {
		for (CertificationPermission certificationPermission : values()) {
			if (code == certificationPermission.getCode()) {
				return certificationPermission;
			}
		}
		throw new IllegalArgumentException(String.format("Not supported /DocMDP code value : %s", code));
	}

}
