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

import java.io.File;
import java.io.InputStream;
import java.util.HashMap;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Digest representation of a {@code FileDocument}. It can be used to handle a large file to be signed. The computation of the digest associated to the file can be done externally.
 */

public class DigestDocument extends FileDocument {

	private static final Logger logger = LoggerFactory.getLogger(DigestDocument.class);

	private HashMap<DigestAlgorithm, String> base64EncodeDigestMap = new HashMap<DigestAlgorithm, String>();

	private String base64Encoded;

	/**
	 * Creates dss document from the path and for which the digest can be provided externally.
	 *
	 * @param path
	 *            the path to the file
	 */
	public DigestDocument(final String path) {
		super(path);
	}

	/**
	 * Creates dss document from the {@code File} and for which the digest can be provided externally.
	 *
	 * @param file
	 *            {@code File}
	 */
	public DigestDocument(final File file) {
		super(file);
	}

	@Override
	public InputStream openStream() throws DSSException {
		throw new DSSUnsupportedOperationException("Cannot open DigestDocument");
	}

	@Override
	public byte[] getBytes() throws DSSException {
		throw new DSSUnsupportedOperationException("The underlying file is too large to convert it into byte array!");
	}

	/**
	 * This method allows to add a pair: {@code DigestAlgorithm} and the corresponding digest value calculated externally on the encapsulated file. The digest value is base 64 encoded.
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
			logger.warn("Inefficient DigestDocument : " + digestAlgorithm + " is missing (use addDigest method)");
			base64EncodeDigest = super.getDigest(digestAlgorithm);
		}
		return base64EncodeDigest;
	}

	/**
	 * This method allows to set the base 64 encoded file
	 */
	public void setBase64Encoded(String base64Encoded) {
		this.base64Encoded = base64Encoded;
	}

	@Override
	public String getBase64Encoded() {
		if (StringUtils.isEmpty(base64Encoded)) {
			logger.warn("Inefficient DigestDocument : base64 encoded is missing (use setBase64Encoded method)");
			return super.getBase64Encoded();
		} else {
			return base64Encoded;
		}
	}
}