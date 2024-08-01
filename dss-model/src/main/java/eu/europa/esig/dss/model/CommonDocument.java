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
import eu.europa.esig.dss.enumerations.MimeType;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
	protected EnumMap<DigestAlgorithm, byte[]> digestMap = new EnumMap<>(DigestAlgorithm.class);

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
		// empty
	}

	@Override
	public void save(final String path) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(path)) {
			writeTo(fos);
		}
	}

	@Override
	public void writeTo(OutputStream stream) throws IOException {
		byte[] buffer = new byte[8192];
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
	public Digest getDigest(final DigestAlgorithm digestAlgorithm) {
		final byte[] digestBytes = getDigestValue(digestAlgorithm);
		return new Digest(digestAlgorithm, digestBytes);
	}

	@Override
	public byte[] getDigestValue(DigestAlgorithm digestAlgorithm) {
		byte[] digest = digestMap.get(digestAlgorithm);
		if (digest == null) {
			try (InputStream is = openStream()) {
				MessageDigest messageDigest = digestAlgorithm.getMessageDigest();
				final byte[] buffer = new byte[8192];
				int count;
				while ((count = is.read(buffer)) > 0) {
					messageDigest.update(buffer, 0, count);
				}
				digest = messageDigest.digest();
				digestMap.put(digestAlgorithm, digest);
			} catch (IOException | NoSuchAlgorithmException e) {
				throw new DSSException("Unable to compute the digest", e);
			}
		}
		return digest;
	}

	@Override
	public String toString() {
		final String mimeTypeString = (mimeType == null) ? "" : mimeType.getMimeTypeString();
		return "Name: " + name + " / MimeType: " + mimeTypeString;
	}

}
