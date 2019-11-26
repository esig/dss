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

import java.util.EnumMap;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;

/**
 * This class is used to obtain a requested digest from a stored binary array
 */
public abstract class MultipleDigestIdentifier extends Identifier {

	private static final long serialVersionUID = 8499261315144968564L;

	private final byte[] binaries;

	private final EnumMap<DigestAlgorithm, byte[]> digestMap = new EnumMap<DigestAlgorithm, byte[]>(DigestAlgorithm.class);
	
	protected MultipleDigestIdentifier(byte[] binaries) {
		super(binaries);
		this.binaries = binaries;
		
		Digest id = getDigestId();
		digestMap.put(id.getAlgorithm(), id.getValue());
	}
	
	public byte[] getBinaries() {
		return binaries;
	}
	
	public byte[] getDigestValue(DigestAlgorithm digestAlgorithm) {
		byte[] digestValue = digestMap.get(digestAlgorithm);
		if (digestValue == null) {
			digestValue = getMessageDigest(digestAlgorithm).digest(getBinaries());
			digestMap.put(digestAlgorithm, digestValue);
		}
		return digestValue;
	}

}
