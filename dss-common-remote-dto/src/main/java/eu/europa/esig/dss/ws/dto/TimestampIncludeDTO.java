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
package eu.europa.esig.dss.ws.dto;

import java.io.Serializable;

/**
 * DTO to represent timestamped references for a XAdES IndividualDataObjectsTimeStamp
 */
public class TimestampIncludeDTO implements Serializable {
	
	private static final long serialVersionUID = -6910516846531402711L;

	/** The URI of the reference to be covered */
	private String uri;

	/**
	 * Defines if the data is references
	 * NOTE: The referencedData attribute shall be present in each and every Include element, and set to "true".
	 */
	private boolean referencedData;

	/**
	 * Empty constructor
	 */
	public TimestampIncludeDTO() {
	}

	/**
	 * The default constructor
	 *
	 * @param uri {@link String} the reference uri
	 * @param referencedData of the data is referenced
	 */
	public TimestampIncludeDTO(String uri, boolean referencedData) {
		this.uri = uri;
		this.referencedData = referencedData;
	}

	/**
	 * Gets the reference URI
	 *
	 * @return {@link String} uri
	 */
	public String getURI() {
		return uri;
	}

	/**
	 * Sets the reference URI
	 *
	 * @param uri {@link String}
	 */
	public void setURI(String uri) {
		this.uri = uri;
	}

	/**
	 * Gets of the data is references
	 *
	 * @return TRUE if the {@code 'referencedData'} attribute value set to true, FALSE otherwise
	 */
	public boolean isReferencedData() {
		return referencedData;
	}

	/**
	 * Sets the value corresponding to {@code 'referencedData'} attribute value
	 *
	 * @param referencedData the value corresponding to {@code 'referencedData'} attribute value
	 */
	public void setReferencedData(boolean referencedData) {
		this.referencedData = referencedData;
	}
}
