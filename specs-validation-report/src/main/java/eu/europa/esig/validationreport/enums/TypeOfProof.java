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
package eu.europa.esig.validationreport.enums;

import eu.europa.esig.dss.enumerations.UriBasedEnum;

/**
 * Defines a TypeOfProof
 */
public enum TypeOfProof implements UriBasedEnum {

	/**
	 * when the POE has been derived during validation
	 */
	VALIDATION("urn:etsi:019102:poetype:validation"),

	/**
	 * when the POE has been provided to the SVA as an input
	 */
	PROVIDED("urn:etsi:019102:poetype:provided"),

	/**
	 * when the POE has been derived by the policy
	 */
	POLICY("urn:etsi:019102:poetype:policy");

	private final String uri;

	TypeOfProof(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
