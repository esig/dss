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
package eu.europa.esig.dss.enumerations;

/**
 * Defines possible timestamp qualification types
 */
public enum TimestampQualification {

	/** Qualified timestamp token */
	QTSA("QTSA", "Qualified timestamp", "urn:cef:dss:timestampQualification:QTSA"),

	/** Not-qualified timestamp token */
	TSA("TSA", "Not qualified timestamp", "urn:cef:dss:timestampQualification:TSA"),

	/** Not-applicable (not determined) */
	NA("N/A", "Not applicable", "urn:cef:dss:timestampQualification:notApplicable");

	/** User-friendly name (abbreviation) of the timestamp qualification */
	private final String readable;

	/** Description of the qualification */
	private final String label;

	/** Unique URL */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param readable {@link String}
	 * @param label {@link String}
	 * @param uri {@link String}
	 */
	TimestampQualification(String readable, String label, String uri) {
		this.readable = readable;
		this.label = label;
		this.uri = uri;
	}

	/**
	 * Returns a short name of the qualification status
	 *
	 * @return {@link String}
	 */
	public String getReadable() {
		return readable;
	}

	/**
	 * Returns a complete name of the qualification status
	 *
	 * @return {@link String}
	 */
	public String getLabel() {
		return label;
	}

	/**
	 * Returns a URI of the qualification status
	 *
	 * @return {@link String}
	 */
	public String getUri() {
		return uri;
	}

}
