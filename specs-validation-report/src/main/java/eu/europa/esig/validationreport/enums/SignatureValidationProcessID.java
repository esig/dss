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
package eu.europa.esig.validationreport.enums;

import eu.europa.esig.dss.enumerations.UriBasedEnum;

/**
 * Defines SignatureValidationProcessID
 */
public enum SignatureValidationProcessID implements UriBasedEnum {

	/**
	 * when the SVA performed the Validation Process for Basic Signatures as
	 * specified in ETSI TS 119 102-1 [1], clause 5.3.
	 */
	BASIC("urn:etsi:019102:validationprocess:Basic"),

	/**
	 * when the SVA performed the Validation Process for Signatures with Time and
	 * Signatures with LongTerm-Validation Material as specified in ETSI TS 119
	 * 102-1 [1], clause 5.5.
	 */
	LTVM("urn:etsi:019102:validationprocess:LTVM"),

	/**
	 * when the SVA performed the Validation process for Signatures providing Long
	 * Term Availability and Integrity of Validation Material as specified in ETSI
	 * TS 119 102-1 [1], clause 5.6.
	 */
	LTA("urn:etsi:019102:validationprocess:LTA");

	private final String uri;

	SignatureValidationProcessID(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
