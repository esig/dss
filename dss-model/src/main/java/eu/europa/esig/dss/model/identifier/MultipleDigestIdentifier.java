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
package eu.europa.esig.dss.model.identifier;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;

import java.util.Arrays;
import java.util.EnumMap;

/**
 * This class is used to obtain a requested digest from a stored binary array
 *
 */
public abstract class MultipleDigestIdentifier extends Identifier {

	private static final long serialVersionUID = 8499261315144968564L;

	/** Binary to compute the identifier for */
	private final byte[] binaries;

	/** Digest map */
	private final EnumMap<DigestAlgorithm, byte[]> digestMap = new EnumMap<>(DigestAlgorithm.class);

	/**
	 * Default constructor
	 *
	 * @param prefix {@link String} for the identifier
	 * @param binaries token binaries
	 */
	protected MultipleDigestIdentifier(final String prefix, byte[] binaries) {
		super(prefix, binaries);
		this.binaries = binaries;
		
		Digest id = getDigestId();
		digestMap.put(id.getAlgorithm(), id.getValue());
	}

	/**
	 * Gets token binaries
	 *
	 * @return byte array
	 */
	public byte[] getBinaries() {
		return binaries;
	}

	/**
	 * Returns a digest value for the given {@code digestAlgorithm}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @return digests
	 */
	public byte[] getDigestValue(DigestAlgorithm digestAlgorithm) {
		return digestMap.computeIfAbsent(digestAlgorithm, k -> getMessageDigest(digestAlgorithm).digest(getBinaries()));
	}

	/**
	 * Checks if the given digests match to the token
	 *
	 * @param expectedDigest {@link Digest} to verify
	 * @return TRUE if the digest match, FALSE otherwise
	 */
	public boolean isMatch(Digest expectedDigest) {
		return Arrays.equals(expectedDigest.getValue(), getDigestValue(expectedDigest.getAlgorithm()));
	}

}
