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

package eu.europa.ec.markt.dss.signature;

import java.io.InputStream;
import java.io.StringWriter;
import java.util.HashMap;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSUnsupportedOperationException;

/**
 * Digest representation of a {@code DSSDocument}. It can be used to handle a large file to be signed.
 *
 * @version $Revision$ - $Date$
 */

public class DigestDocument implements DSSDocument {

	private HashMap<DigestAlgorithm, String> base64EncodeDigestMap = new HashMap<DigestAlgorithm, String>();

	private String name;

	private String absolutePath;

	private MimeType mimeType;

	/**
	 * Creates dss document that retains only the digest of the document.
	 *
	 * @param name the file name if the data originates from a file
	 */
	public DigestDocument(final String name) {

		this.name = name;
		this.mimeType = MimeType.fromFileName(name);
	}

	/**
	 * Creates dss document that retains only the digest of the document.
	 *
	 * @param name     the file name if the data originates from a file
	 * @param mimeType the mime type of the file if the data originates from a file
	 */
	public DigestDocument(final String name, final MimeType mimeType) {

		this.name = name;
		this.mimeType = mimeType;
	}

	@Override
	public InputStream openStream() throws DSSException {

		throw new DSSUnsupportedOperationException("...");
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public MimeType getMimeType() {
		return mimeType;
	}

	@Override
	public byte[] getBytes() throws DSSException {

		throw new DSSUnsupportedOperationException("A DigestDocument does not contains document but only its digest!");
	}

	public void setName(final String name) {
		this.name = name;
	}

	public void setMimeType(final MimeType mimeType) {
		this.mimeType = mimeType;
	}

	public void setAbsolutePath(final String absolutePath) {
		this.absolutePath = absolutePath;
	}

	@Override
	public void save(final String filePath) {

		throw new DSSUnsupportedOperationException("A DigestDocument does not contains document but only its digest!");
	}

	@Override
	public String getAbsolutePath() {

		return absolutePath;
	}

	public void addDigest(final DigestAlgorithm digestAlgorithm, final String base64EncodeDigest) {

		base64EncodeDigestMap.put(digestAlgorithm, base64EncodeDigest);
	}

	@Override
	public String getDigest(final DigestAlgorithm digestAlgorithm) {

		return base64EncodeDigestMap.get(digestAlgorithm);
	}

	@Override
	public String toString() {

		final StringWriter stringWriter = new StringWriter();
		final MimeType mimeType = getMimeType();
		final String name = getName();
		if (name != null) {

			stringWriter.append("Name: ").append(name).append(" / ");
		}
		if (mimeType != null) {

			stringWriter.append(mimeType.name()).append(" / ");
		}
		stringWriter.append(getAbsolutePath());
		final String string = stringWriter.toString();
		return string;
	}
}