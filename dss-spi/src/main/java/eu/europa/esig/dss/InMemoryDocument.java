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
package eu.europa.esig.dss;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import eu.europa.esig.dss.utils.Utils;

/**
 * In memory representation of a document
 *
 */
public class InMemoryDocument extends CommonDocument {

	private byte[] bytes;

	public InMemoryDocument() {
	}

	/**
	 * Creates dss document that retains the data in memory
	 *
	 * @param bytes
	 *            array of bytes representing the document
	 */
	public InMemoryDocument(final byte[] bytes) {
		this(bytes, null, null);
	}

	/**
	 * Creates dss document that retains the data in memory
	 *
	 * @param bytes
	 *            array of bytes representing the document
	 * @param name
	 *            the file name if the data originates from a file
	 */
	public InMemoryDocument(final byte[] bytes, final String name) {
		this.bytes = bytes;
		this.name = name;
		this.mimeType = MimeType.fromFileName(name);
	}

	/**
	 * Creates dss document that retains the data in memory
	 *
	 * @param bytes
	 *            array of bytes representing the document
	 * @param name
	 *            the file name if the data originates from a file
	 * @param mimeType
	 *            the mime type of the file if the data originates from a file
	 */
	public InMemoryDocument(final byte[] bytes, final String name, final MimeType mimeType) {
		this.bytes = bytes;
		this.name = name;
		this.mimeType = mimeType;
	}

	/**
	 * Creates dss document that retains the data in memory
	 *
	 * @param inputStream
	 *            input stream representing the document
	 */
	public InMemoryDocument(final InputStream inputStream) {
		this(DSSUtils.toByteArray(inputStream), null, null);
	}

	/**
	 * Creates dss document that retains the data in memory
	 *
	 * @param inputStream
	 *            input stream representing the document
	 * @param name
	 *            the file name if the data originates from a file
	 */
	public InMemoryDocument(final InputStream inputStream, final String name) {
		this(DSSUtils.toByteArray(inputStream), name);
	}

	/**
	 * Creates dss document that retains the data in memory
	 *
	 * @param inputStream
	 *            input stream representing the document
	 * @param name
	 *            the file name if the data originates from a file
	 * @param mimeType
	 *            the mime type of the file if the data originates from a file
	 */
	public InMemoryDocument(final InputStream inputStream, final String name, final MimeType mimeType) {
		this(DSSUtils.toByteArray(inputStream), name, mimeType);
	}

	@Override
	public InputStream openStream() {
		return new ByteArrayInputStream(bytes);
	}

	public byte[] getBytes() {
		return bytes;
	}

	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
	}

	public String getBase64Encoded() {
		return Utils.toBase64(bytes);
	}

}
