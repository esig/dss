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
 * Defines result of signature validation for a token
 */
public enum SignatureValidity {

	/** The signature of the token is valid (signing certificate found successfully) */
	VALID,

	/** The signature of the token is invalid */
	INVALID,

	/** The signature of the token is not evaluated yet */
	NOT_EVALUATED;

	/**
	 * Returns the SignatureValidity type matching the given value
	 *
	 * @param isValid {@link Boolean} type of the signatureValidity to request
	 * @return {@link SignatureValidity}
	 */
	public static SignatureValidity get(Boolean isValid) {
		if (isValid == null) {
			return NOT_EVALUATED;
		} else if (isValid) {
			return VALID;
		} else {
			return INVALID;
		}
	}

}
