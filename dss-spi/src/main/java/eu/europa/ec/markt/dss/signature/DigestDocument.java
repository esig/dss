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

import java.io.File;
import java.util.HashMap;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSUnsupportedOperationException;

/**
 * Digest representation of a {@code FileDocument}. It can be used to handle a large file to be signed. The computation of the digest associated to the file can be done externally.
 *
 * @version $Revision$ - $Date$
 */

public class DigestDocument extends FileDocument {

	private HashMap<DigestAlgorithm, String> base64EncodeDigestMap = new HashMap<DigestAlgorithm, String>();

	/**
	 * Creates dss document from the path and for which the digest can be provided externally.
	 *
	 * @param path the path to the file
	 */
	public DigestDocument(final String path) {

		super(path);
	}

	/**
	 * Creates dss document from the {@code File} and for which the digest can be provided externally.
	 *
	 * @param file {@code File}
	 */
	public DigestDocument(final File file) {

		super(file);
	}

	@Override
	public byte[] getBytes() throws DSSException {

		throw new DSSUnsupportedOperationException("The underlying file is too large to convert it into byte array!");
	}

	/**
	 * This method allows to add a pair: {@code DigestAlgorithm} and the corresponding digest value calculated externally on the encapsulated file. The digest value is base 64 encoded.
	 *
	 * @param digestAlgorithm {@code DigestAlgorithm}
	 * @param base64EncodeDigest the corresponding base 64 encoded digest value
	 */
	public void addDigest(final DigestAlgorithm digestAlgorithm, final String base64EncodeDigest) {

		base64EncodeDigestMap.put(digestAlgorithm, base64EncodeDigest);
	}

	@Override
	public String getDigest(final DigestAlgorithm digestAlgorithm) {

		String base64EncodeDigest = base64EncodeDigestMap.get(digestAlgorithm);
		if (base64EncodeDigest == null) {
			base64EncodeDigest = super.getDigest(digestAlgorithm);
		}
		return base64EncodeDigest;
	}
}