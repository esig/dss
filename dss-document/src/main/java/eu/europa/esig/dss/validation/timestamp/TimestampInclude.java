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

/**
 * This class represents XAdES Include tag in case of IndividualDataObjectsTimeStamp
 */
public class TimestampInclude {

	private String uri;
	/* The referencedData attribute shall be present in each and every Include element, and set to "true". */
	private boolean referencedData;

	public TimestampInclude() {
	}

	public TimestampInclude(String uri, boolean referencedData) {
		this.uri = uri;
		this.referencedData = referencedData;
	}

	public String getURI() {
		return uri;
	}

	public void setURI(String uri) {
		this.uri = uri;
	}

	public boolean isReferencedData() {
		return referencedData;
	}

	public void setReferencedData(boolean referencedData) {
		this.referencedData = referencedData;
	}

}
