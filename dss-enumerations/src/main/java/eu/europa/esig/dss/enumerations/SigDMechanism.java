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
 * This Enumeration defines a list of algorithm described in ETSI TS 119 182-1
 * for incorporation of 'sigD' dictionary (see 5.2.8 The sigD header parameter)
 *
 */
public enum SigDMechanism implements UriBasedEnum {
	
	/**
	 * 5.2.8.2	Mechanism HttpHeaders
	 */
	HTTP_HEADERS("http://uri.etsi.org/19182/HttpHeaders"),

	/**
	 * 5.2.8.3.2	Mechanism ObjectIdByURI
	 */
	OBJECT_ID_BY_URI("http://uri.etsi.org/19182/ObjectIdByURI"),

	/**
	 * 5.2.8.3.3	Mechanism ObjectIdByURIHash
	 * 
	 * NOTE: the default signature creation mechanism used by DSS
	 */
	OBJECT_ID_BY_URI_HASH("http://uri.etsi.org/19182/ObjectIdByURIHash"),
	
	/**
	 * Creates a simple DETACHED signature with omitted payload (without SigD element)
	 */
	NO_SIG_D("");
	
	private final String uri;
	
	SigDMechanism(final String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}
	
	/**
	 * Returns a SigDMechanism for the given URI
	 * 
	 * @param uri {@link String} URI representing a SigDMechanism
	 * @return {@link SigDMechanism}
	 */
	public static SigDMechanism forUri(final String uri) {
		for (SigDMechanism sigDMechanism : values()) {
			if (sigDMechanism.getUri().equals(uri)) {
				return sigDMechanism;
			}
		}
		return null;
	}

}
