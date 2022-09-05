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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.enumerations.MimeType;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * The class represents an HTTP Header to be signed
 * See ETSI TS 119 182-1 "5.2.8.2 Mechanism HttpHeaders"
 * 
 * The class shall be used only for JAdES detached {@code SigDMechanism.HTTP_HEADERS} mechanism
 *
 */
@SuppressWarnings("serial")
public class HTTPHeader implements DSSDocument {

	/** The HTTP Header's name */
	private final String name;

	/** The HTTP Header's value */
	private String value;

	/**
	 * The default constructor
	 *
	 * @param name {@link String} of the header
	 * @param value {@link String} of the header
	 */
	public HTTPHeader(final String name, final String value) {
		this.name = name;
		this.value = value;
	}

	/**
	 * Returns a String name (key) of the HTTP Header
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Returns a String value of the HTTP Header
	 * 
	 * @return {@link String} value
	 */
	public String getValue() {
		return value;
	}

	/**
	 * Sets a String value of HTTP Header
	 * 
	 * @param value {@link String} value
	 */
	public void setValue(String value) {
		this.value = value;
	}

	@Override
	public InputStream openStream() {
		throw new UnsupportedOperationException("The openStream() method is not supported for HTTPHeaderDocument.");
	}

	@Override
	public void writeTo(OutputStream stream) throws IOException {
		throw new UnsupportedOperationException("The writeTo(stream) method is not supported for HTTPHeaderDocument.");
	}

	@Override
	public void setName(String name) {
		throw new UnsupportedOperationException("The setName(name) method is not supported for HTTPHeaderDocument.");
	}

	@Override
	public MimeType getMimeType() {
		// not applicable
		return null;
	}

	@Override
	public void setMimeType(MimeType mimeType) {
		throw new UnsupportedOperationException("The setMimeType(mimeType) method is not supported for HTTPHeaderDocument.");
	}

	@Override
	public void save(String filePath) throws IOException {
		throw new UnsupportedOperationException("The save(filePath) method is not supported for HTTPHeaderDocument.");
	}

	@Override
	public String getDigest(DigestAlgorithm digestAlgorithm) {
		throw new UnsupportedOperationException("The getDigest(digestAlgorithm) method is not supported for HTTPHeaderDocument.");
	}

}
