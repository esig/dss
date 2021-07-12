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
package eu.europa.esig.dss.validation.timestamp;

import java.io.Serializable;

/**
 * This class represents XAdES Include tag in case of IndividualDataObjectsTimeStamp
 */
public class TimestampInclude implements Serializable {

	private static final long serialVersionUID = 8557108386646000784L;

	/** The reference URI */
	private String uri;

	/** The referencedData attribute shall be present in each and every Include element, and set to "true". */
	private boolean referencedData;

	/**
	 * Empty constructor
	 */
	public TimestampInclude() {
	}

	/**
	 * Default constructor
	 *
	 * @param uri {@link String} reference URI
	 * @param referencedData if the reference is timestamped
	 */
	public TimestampInclude(String uri, boolean referencedData) {
		this.uri = uri;
		this.referencedData = referencedData;
	}

	/**
	 * Gets the reference URI
	 *
	 * @return {@link String}
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
	 * Returns if the data is referenced
	 *
	 * @return TRUE if the reference is timestamped, FALSE otherwise
	 */
	public boolean isReferencedData() {
		return referencedData;
	}

	/**
	 * Sets if the data is referenced
	 *
	 * @param referencedData if the reference is timestamped
	 */
	public void setReferencedData(boolean referencedData) {
		this.referencedData = referencedData;
	}

}
