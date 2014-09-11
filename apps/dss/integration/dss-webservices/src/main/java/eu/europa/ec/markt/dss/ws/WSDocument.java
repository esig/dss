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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.Arrays;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.CommonDocument;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

/**
 * Container for any kind of document that is to be transferred to and from web service endpoints.
 *
 * @version $Revision$ - $Date$
 */

public class WSDocument extends CommonDocument {

	private byte[] bytes;

	private String name = "WSDocument";

	/**
	 * The mime-type is transported as {@code String}
	 */
	private String mimeTypeString = "";

	private String absolutePath = "WSDocument";

	/**
	 * This constructor is used by Spring in the web-app..
	 */
	public WSDocument() {

	}

	/**
	 * The default constructor for WSDocument.
	 *
	 * @param doc
	 * @throws IOException
	 */
	public WSDocument(final DSSDocument doc) throws DSSException {

		final byte[] bytes = doc.getBytes();
		this.bytes = Arrays.copyOf(bytes, bytes.length);
		mimeType = doc.getMimeType();
		if (mimeType != null) {
			mimeTypeString = mimeType.getCode();
		}
		name = doc.getName();
		absolutePath = doc.getAbsolutePath();
	}

	/**
	 * This method is used by web services
	 *
	 * @return the bytes
	 */
	@Override
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

	@Override
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
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

	@Override
	public InputStream openStream() throws DSSException {

		final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
		return byteArrayInputStream;
	}

	@Override
	public void save(final String filePath) {

		try {

			final FileOutputStream fos = new FileOutputStream(filePath);
			DSSUtils.write(getBytes(), fos);
			fos.close();
		} catch (FileNotFoundException e) {
			throw new DSSException(e);
		} catch (DSSException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public String getDigest(final DigestAlgorithm digestAlgorithm) {

		final byte[] digestBytes = DSSUtils.digest(digestAlgorithm, getBytes());
		final String base64Encode = DSSUtils.base64Encode(digestBytes);
		return base64Encode;
	}

	@Override
	public String toString() {

		final StringWriter stringWriter = new StringWriter();
		final MimeType mimeType = getMimeType();
		stringWriter.append("Name: " + getName()).append(" / ").append(mimeType == null ? "mime-type=null" : getMimeType().name()).append(" / ").append("mime-type-string=")
			  .append(mimeTypeString).append(" / ").append(getAbsolutePath());
		final String string = stringWriter.toString();
		return string;
	}
}