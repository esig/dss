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
		// empty
	}

	/**
	 * Creates DigestDocument with an initial {@code Digest}
	 *
	 * @param digest
	 *            {@code Digest} for the new DigestDocument
	 */
	public DigestDocument(final Digest digest) {
		Objects.requireNonNull(digest, "The Digest is not defined");
		addDigest(digest);
	}

	/**
	 * Creates DigestDocument with an initial {@code Digest} and a specified document {@code name}
	 *
	 * @param digest
	 *            {@code Digest} for the new DigestDocument
	 * @param name
	 * 			  {@link String} name of the document
	 */
	public DigestDocument(final Digest digest, final String name) {
		this(digest, name, MimeType.fromFileName(name));
	}

	/**
	 * Creates DigestDocument with an initial {@code Digest}, a specified {@code name} and {@code mimeType} of the document
	 *
	 * @param digest
	 *            {@code Digest} for the new DigestDocument
	 * @param name
	 * 			  {@link String} name of the document
	 * @param mimeType
	 * 			  {@link MimeType} of the document
	 */
	public DigestDocument(final Digest digest, final String name, final MimeType mimeType) {
		this(digest);
		this.name = name;
		this.mimeType = mimeType;
	}

	/**
	 * Creates DigestDocument with a digest provided in a form of byte array
	 *
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm}
	 * @param digestValue
	 *            byte array representing the corresponding digest value
	 */
	public DigestDocument(final DigestAlgorithm digestAlgorithm, final byte[] digestValue) {
		addDigest(digestAlgorithm, digestValue);
	}

	/**
	 * Creates DigestDocument with a digest provided in a form of base64-encoded String
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
	 * Creates DigestDocument with a digest provided in a form of byte array with a specified document name
	 *
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm}
	 * @param digestValue
	 *            byte array representing the corresponding digest value
	 * @param name
	 *            the name of the document
	 */
	public DigestDocument(final DigestAlgorithm digestAlgorithm, final byte[] digestValue, final String name) {
		this(digestAlgorithm, digestValue, name, MimeType.fromFileName(name));
	}

	/**
	 * Creates DigestDocument with a digest provided in a form of byte array with a specified
	 * {@code name} and {@code mimeType} of the document
	 *
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm}
	 * @param digestValue
	 *            byte array representing the corresponding digest value
	 * @param name
	 *            the name of the document
	 * @param mimeType
	 *            the mymetype of the document
	 */
	public DigestDocument(final DigestAlgorithm digestAlgorithm, final byte[] digestValue, final String name,
						  final MimeType mimeType) {
		this(digestAlgorithm, digestValue);
		this.name = name;
		this.mimeType = mimeType;
	}

	/**
	 * Creates DigestDocument with a digest provided in a form of base64-encoded String with a specified document name
	 * 
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm}
	 * @param base64EncodeDigest
	 *            the corresponding base 64 encoded digest value
	 * @param name
	 *            the name of the document
	 */
	public DigestDocument(final DigestAlgorithm digestAlgorithm, final String base64EncodeDigest, final String name) {
		this(digestAlgorithm, base64EncodeDigest, name, MimeType.fromFileName(name));
	}

	/**
	 * Creates DigestDocument with a digest provided in a form of base64-encoded String with
	 * a specified {@code name} and {@code mimeType} of the document
	 *
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm}
	 * @param base64EncodeDigest
	 *            the corresponding base 64 encoded digest value
	 * @param name
	 *            the name of the document
	 * @param mimeType
	 * 			  the mimetype of the document
	 */
	public DigestDocument(final DigestAlgorithm digestAlgorithm, final String base64EncodeDigest, final String name,
						  final MimeType mimeType) {
		this(digestAlgorithm, base64EncodeDigest);
		this.name = name;
		this.mimeType = mimeType;
	}

	/**
	 * This method allows to add a {@code Digest} with a new digest algorithm to the current DigestDocument.
	 * Overwrites the previous digest if the same DigestAlgorithm is provided.
	 *
	 * @param digest
	 *            {@link Digest} for the current document
	 */
	public void addDigest(final Digest digest) {
		Objects.requireNonNull(digest, "The Digest is not defined");
		addDigest(digest.getAlgorithm(), digest.getValue());
	}

	/**
	 * This method allows to add a pair: {@code DigestAlgorithm} and the corresponding digest value calculated
	 * externally on the encapsulated file.
	 *
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm} used ot compute the digest value
	 * @param digestValue
	 *            byte array representing the corresponding digest value
	 */
	public void addDigest(final DigestAlgorithm digestAlgorithm, final byte[] digestValue) {
		Objects.requireNonNull(digestAlgorithm, "The Digest Algorithm is not defined");
		Objects.requireNonNull(digestValue, "The digest value is not defined");
		digestMap.put(digestAlgorithm, digestValue);
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
		Objects.requireNonNull(base64EncodeDigest, "The digest value is not defined");
		byte[] digest;
		try {
			digest = Base64.getDecoder().decode(base64EncodeDigest);
		} catch (Exception e) {
			throw new IllegalArgumentException(
					String.format("Unable to base64-decode string '%s' : %s", base64EncodeDigest, e.getMessage()));
		}
		addDigest(digestAlgorithm, digest);
	}

	@Override
	public byte[] getDigestValue(DigestAlgorithm digestAlgorithm) {
		byte[] digestValue = digestMap.get(digestAlgorithm);
		if (digestValue == null) {
			throw new IllegalArgumentException("The digest document does not contain a digest value for the algorithm : " + digestAlgorithm);
		}
		return digestValue;
	}

	/**
	 * Gets the defined digest value for the DigestDocument
	 *
	 * @return {@link Digest}
	 */
	public Digest getExistingDigest() {
		if (!digestMap.isEmpty()) {
			Entry<DigestAlgorithm, byte[]> digestEntry = digestMap.entrySet().iterator().next();
			return new Digest(digestEntry.getKey(), digestEntry.getValue());
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

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		DigestDocument that = (DigestDocument) o;
		return Objects.equals(digestMap, that.digestMap)
				&& Objects.equals(mimeType, that.mimeType)
				&& Objects.equals(name, that.name);

	}

}
