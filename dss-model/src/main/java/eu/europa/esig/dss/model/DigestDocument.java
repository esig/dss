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

import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Map.Entry;
import java.util.Objects;

/**
 * Digest representation of a {@code DSSDocument}. It can be used to handle a large file to be signed. The computation
 * of the digest associated to the file can be done externally.
 */
@SuppressWarnings("serial")
public class DigestDocument extends CommonDocument {
	
	/**
	 * Creates DigestDocument with an empty digest map.
	 * Initial algorithm and digest must be specified in order to use the object
	 */
	public DigestDocument() {
	}

	/**
	 * Creates DigestDocument.
	 * 
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm}
	 * @param base64EncodeDigest
	 *            the corresponding base 64 encoded digest value
	 */
	public DigestDocument(final DigestAlgorithm digestAlgorithm, final String base64EncodeDigest) {
		addDigest(digestAlgorithm, base64EncodeDigest);
	}

	/**
	 * Creates DigestDocument.
	 * 
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm}
	 * @param base64EncodeDigest
	 *            the corresponding base 64 encoded digest value
	 * @param name
	 *            the name of the document
	 */
	public DigestDocument(final DigestAlgorithm digestAlgorithm, final String base64EncodeDigest, final String name) {
		this(digestAlgorithm, base64EncodeDigest);
		this.name = name;
	}

	/**
	 * This method allows to add a pair: {@code DigestAlgorithm} and the corresponding digest value calculated
	 * externally on the encapsulated file. The digest value is base 64 encoded.
	 *
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm}
	 * @param base64EncodeDigest
	 *            the corresponding base 64 encoded digest value
	 */
	public void addDigest(final DigestAlgorithm digestAlgorithm, final String base64EncodeDigest) {
		Objects.requireNonNull(digestAlgorithm, "The Digest Algorithm is not defined");
		Objects.requireNonNull(base64EncodeDigest, "The digest value is not defined");
		base64EncodeDigestMap.put(digestAlgorithm, base64EncodeDigest);
	}

	@Override
	public String getDigest(final DigestAlgorithm digestAlgorithm) {
		String base64EncodeDigest = base64EncodeDigestMap.get(digestAlgorithm);
		if (base64EncodeDigest == null) {
			throw new IllegalArgumentException("The digest document does not contain a digest value for the algorithm : " + digestAlgorithm);
		}
		return base64EncodeDigest;
	}

	/**
	 * Gets the defined digest value for the DigestDocument
	 *
	 * @return {@link Digest}
	 */
	public Digest getExistingDigest() {
		if (!base64EncodeDigestMap.isEmpty()) {
			Entry<DigestAlgorithm, String> digestEntry = base64EncodeDigestMap.entrySet().iterator().next();
			return new Digest(digestEntry.getKey(), Base64.getDecoder().decode(digestEntry.getValue()));
		}
		throw new IllegalStateException("The DigestDocument does not contain any digest! You must specify it by using addDigest() method.");
	}

	@Override
	public InputStream openStream() {
		throw new UnsupportedOperationException("Not possible with Digest document");
	}

	@Override
	public void save(String filePath) throws IOException {
		throw new UnsupportedOperationException("Not possible with Digest document");
	}

}
