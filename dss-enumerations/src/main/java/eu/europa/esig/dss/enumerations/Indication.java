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
 * The list of possible values for indications.
 * 
 * Source ETSI EN 319 102-1
 */
public enum Indication implements UriBasedEnum {

	// When present in the validation report of a signature, the following URIs
	// shall be used to represent the main status indication:
	TOTAL_PASSED("urn:etsi:019102:mainindication:total-passed"),

	TOTAL_FAILED("urn:etsi:019102:mainindication:total-failed"),

	INDETERMINATE("urn:etsi:019102:mainindication:indeterminate"),

	// When present in an individual validation constraint report element (see
	// clause 4.3.5.4) or a validation report of a signature validation object (see
	// clause 4.4.8), the following URIs shall be used to represent the main status
	// indication:
	PASSED("urn:etsi:019102:mainindication:passed"),

	FAILED("urn:etsi:019102:mainindication:failed"),

	// Empty report is not permitted
	NO_SIGNATURE_FOUND("urn:cef:dss:mainindication:noSignatureFound");

	private final String uri;

	Indication(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
