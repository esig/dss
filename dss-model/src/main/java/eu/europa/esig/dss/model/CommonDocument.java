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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.EnumMap;

/**
 * This class implements the default methods.
 *
 */
@SuppressWarnings("serial")
public abstract class CommonDocument implements DSSDocument {

	/**
	 * Cached map of DigestAlgorithms and the corresponding digests for the document
	 */
	protected EnumMap<DigestAlgorithm, String> base64EncodeDigestMap = new EnumMap<>(
			DigestAlgorithm.class);

	/**
	 * The MimeType of the document
	 */
	protected MimeType mimeType;

	/**
	 * The document name
	 */
	protected String name;

	/**
	 * Default constructor instantiating object with null values and empty digest map
	 */
	protected CommonDocument() {
	}

	@Override
	public void save(final String path) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(path)) {
			writeTo(fos);
		}
	}

	@Override
	public void writeTo(OutputStream stream) throws IOException {
		byte[] buffer = new byte[1024];
		int count = -1;
		try (InputStream inStream = openStream()) {
			while ((count = inStream.read(buffer)) > 0) {
				stream.write(buffer, 0, count);
			}
		}
	}

	@Override
	public MimeType getMimeType() {
		return mimeType;
	}

	@Override
	public void setMimeType(final MimeType mimeType) {
		this.mimeType = mimeType;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void setName(String name) {
		this.name = name;
	}

	@Override
	public String getDigest(final DigestAlgorithm digestAlgorithm) {
		String base64EncodeDigest = base64EncodeDigestMap.get(digestAlgorithm);
		if (base64EncodeDigest == null) {
			try (InputStream is = openStream()) {
				MessageDigest messageDigest = digestAlgorithm.getMessageDigest();
				final byte[] buffer = new byte[4096];
				int count = 0;
				while ((count = is.read(buffer)) > 0) {
					messageDigest.update(buffer, 0, count);
				}
				final byte[] digestBytes = messageDigest.digest();
				base64EncodeDigest = Base64.getEncoder().encodeToString(digestBytes);
				base64EncodeDigestMap.put(digestAlgorithm, base64EncodeDigest);
			} catch (IOException | NoSuchAlgorithmException e) {
				throw new DSSException("Unable to compute the digest", e);
			}
		}
		return base64EncodeDigest;
	}

	@Override
	public String toString() {
		final StringWriter stringWriter = new StringWriter();
		stringWriter.append("Name: ").append(getName()).append(" / MimeType: ")
				.append(mimeType == null ? "" : mimeType.getMimeTypeString());
		return stringWriter.toString();
	}

}
