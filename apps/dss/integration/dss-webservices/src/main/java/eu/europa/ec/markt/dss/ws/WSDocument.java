/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.ws;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.Arrays;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

/**
 * Container for any kind of document that is to be transferred to and from web service endpoints.
 *
 * @version $Revision$ - $Date$
 */

public class WSDocument {

	private byte[] bytes;

	private String name = "WSDocument";

	protected MimeType mimeType;

	/**
	 * The mime-type is transported as {@code String}
	 */
	private String mimeTypeString = "";

	private String absolutePath = "WSDocument";


	protected WSDocument nextDocument;

	/**
	 * This constructor is used by Spring in the web-app..
	 */
	public WSDocument() {

	}

	/**
	 * The default constructor for WSDocument.
	 *
	 * @param dssDocument
	 * @throws DSSException
	 */
	public WSDocument(final DSSDocument dssDocument) throws DSSException {

		final byte[] bytes = dssDocument.getBytes();
		this.bytes = Arrays.copyOf(bytes, bytes.length);
		mimeType = dssDocument.getMimeType();
		if (mimeType != null) {
			mimeTypeString = mimeType.getCode();
		}
		name = dssDocument.getName();
		absolutePath = dssDocument.getAbsolutePath();

		final DSSDocument nextDssDocument = dssDocument.getNextDocument();
		if (nextDssDocument != null) {
			nextDocument = new WSDocument(nextDssDocument);
		}
	}

	/**
	 * This method is used by web services
	 *
	 * @return the bytes
	 */
	public byte[] getBytes() {

		return bytes;
	}

	/**
	 * This method is used by web services
	 *
	 * @param bytes the bytes to set
	 */
	public void setBytes(byte[] bytes) {

		this.bytes = bytes;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public MimeType getMimeType() {
		return mimeType;
	}

	public void setMimeType(final MimeType mimeType) {
		this.mimeType = mimeType;
	}

	public String getMimeTypeString() {
		return mimeTypeString;
	}

	public void setMimeTypeString(String mimeTypeString) {
		this.mimeTypeString = mimeTypeString;
	}

	public String getAbsolutePath() {
		return absolutePath;
	}

	public void setAbsolutePath(String absolutePath) {
		this.absolutePath = absolutePath;
	}

	public InputStream openStream() throws DSSException {

		final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
		return byteArrayInputStream;
	}

	public WSDocument getNextDocument() {
		return nextDocument;
	}

	public void setNextDocument(WSDocument nextDocument) {
		this.nextDocument = nextDocument;
	}

	@Override
	public String toString() {

		final StringWriter stringWriter = new StringWriter();
		final MimeType mimeType = getMimeType();
		stringWriter.append("Name: " + getName()).append(" / ").append(mimeType == null ? "mime-type=null" : getMimeType().name()).append(" / ").append("mime-type-string=")
			  .append(mimeTypeString).append(" / AbsolutePath [").append(getAbsolutePath()).append("] / nextDocument [").append(nextDocument.toString()).append("]");
		final String string = stringWriter.toString();
		return string;
	}
}