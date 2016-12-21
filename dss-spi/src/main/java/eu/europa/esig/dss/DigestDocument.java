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

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Digest representation of a {@code DSSDocument}. It can be used to handle a large file to be signed. The computation
 * of the digest associated to the file can be done externally.
 */
public class DigestDocument extends CommonDocument {

	private Map<DigestAlgorithm, String> base64EncodeDigestMap = new HashMap<DigestAlgorithm, String>();

	/**
	 * Creates DigestDocument.
	 *
	 */
	public DigestDocument() {
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
		base64EncodeDigestMap.put(digestAlgorithm, base64EncodeDigest);
	}

	@Override
	public String getDigest(final DigestAlgorithm digestAlgorithm) {
		String base64EncodeDigest = base64EncodeDigestMap.get(digestAlgorithm);
		if (base64EncodeDigest == null) {
			throw new DSSException("Unknown digest value for algorithm : " + digestAlgorithm);
		}
		return base64EncodeDigest;
	}

	@Override
	public InputStream openStream() throws DSSException {
		throw new DSSException("Digest document");
	}

	@Override
	public void save(String filePath) throws IOException {
		throw new DSSException("Digest document");
	}

}