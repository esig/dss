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
package eu.europa.esig.dss.model.identifier;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * The DSS identifier for a SignedData
 */
public final class DataIdentifier extends Identifier {

	private static final long serialVersionUID = -9023635708755646223L;

	/**
	 * Default constructor
	 *
	 * @param data the signed data binaries
	 */
	public DataIdentifier(final byte[] data) {
		super("D-", data);
	}

	/**
	 * Constructor to build an identifier based on {@code name} and {@code document}
	 *
	 * @param name {@link String} name of the document to use
	 * @param document {@link DSSDocument} to build an identifier for
	 */
	public DataIdentifier(final String name, final DSSDocument document) {
		this(build(name, document));
	}

	/**
	 * Builds the data byte array for a {@code document} with given {@code name}
	 *
	 * @param name {@link String} name of the document to use
	 * @param document {@link DSSDocument} which content to use for identifier builder
	 * @return byte array
	 */
	private static byte[] build(String name, DSSDocument document) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
			if (name != null) {
				dos.writeChars(name);
			}
			Digest dataDigest = getDigest(document);
			if (dataDigest != null) {
				dos.write(dataDigest.getValue());
			}
			dos.flush();

			return baos.toByteArray();

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to build a JAdESAttributeIdentifier. Reason : %s", e.getMessage()), e);
		}
	}

	/**
	 * Gets digests of the document
	 *
	 * @param document {@link DSSDocument}
	 * @return {@link Digest}
	 */
	private static Digest getDigest(DSSDocument document) {
		if (document != null) {
			if (document instanceof DigestDocument) {
				return ((DigestDocument) document).getExistingDigest();
			} else {
				return new Digest(DIGEST_ALGO, document.getDigestValue(DIGEST_ALGO));
			}
		}
		return null;
	}

}
