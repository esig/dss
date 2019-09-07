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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;

/**
 * A signature reference element references a specific electronic signature.
 * Contains Digest of a referenced signature
 */
public class SignatureDigestReference {
	
	private String canonicalizationMethod;
	private final Digest digest;
	
	public SignatureDigestReference(Digest digest) {
		this.digest = digest;
	}
	
	public SignatureDigestReference(String canonicalizationMethod, Digest digest) {
		this.canonicalizationMethod = canonicalizationMethod;
		this.digest = digest;
	}
	
	/**
	 * Returns canonicalization method used to calculate digest
	 * @return {@link String}
	 */
	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}
	
	/**
	 * Returns {@code DigestAlgorithm} used to calculate digest value
	 * @return {@link DigestAlgorithm}
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digest.getAlgorithm();
	}
	
	/**
	 * Returns calculated digest value
	 * @return byte array
	 */
	public byte[] getDigestValue() {
		return digest.getValue();
	}
	
}
