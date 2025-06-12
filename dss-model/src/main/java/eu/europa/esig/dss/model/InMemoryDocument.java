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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.MimeType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * In memory representation of a document
 *
 */
@SuppressWarnings("serial")
public class InMemoryDocument extends CommonDocument {

	/** The binary content of the document */
	private byte[] bytes;

	/**
	 * Empty constructor
	 */
	public InMemoryDocument() {
		// empty
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
		this(bytes, name, MimeType.fromFileName(name));
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
		Objects.requireNonNull(bytes, "Bytes cannot be null");
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
		this(toByteArray(inputStream), null, null);
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
		this(toByteArray(inputStream), name);
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
		this(toByteArray(inputStream), name, mimeType);
	}

	private static byte[] toByteArray(InputStream inputStream) {
		Objects.requireNonNull(inputStream, "The InputStream is null");
		try (InputStream is = inputStream; ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			int nRead;
			byte[] data = new byte[8192];
			while ((nRead = is.read(data, 0, data.length)) != -1) {
				baos.write(data, 0, nRead);
			}
			return baos.toByteArray();
		} catch (Exception e) {
			throw new DSSException("Unable to fully read the InputStream", e);
		}
	}

	/**
	 * Creates an empty in memory document
	 *
	 * @return {@link InMemoryDocument}
	 */
	public static InMemoryDocument createEmptyDocument() {
		return new InMemoryDocument(new byte[0]);
	}

	@Override
	public InputStream openStream() {
		Objects.requireNonNull(bytes, "Byte array is not defined!");
		return new ByteArrayInputStream(bytes);
	}

	/**
	 * Gets binary content of the document
	 *
	 * @return byte array
	 */
	public byte[] getBytes() {
		return bytes;
	}

	/**
	 * Sets binary content of the document
	 *
	 * @param bytes byte array
	 */
	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
	}

	/**
	 * Gets base64-encoded content of the document
	 *
	 * @return {@link String} base64 encoded
	 */
	public String getBase64Encoded() {
		Objects.requireNonNull(bytes, "Byte array is not defined!");
		return Base64.getEncoder().encodeToString(bytes);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;

		InMemoryDocument that = (InMemoryDocument) o;
		return Arrays.equals(bytes, that.bytes);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + Arrays.hashCode(bytes);
		return result;
	}
	
}
