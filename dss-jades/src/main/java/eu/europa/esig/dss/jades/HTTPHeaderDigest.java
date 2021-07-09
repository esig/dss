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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.Objects;

/**
 * An HTTP message body, which 'Digest' representation is being signed with 'sigD' HTTP_HEADERS mechanism
 *
 */
@SuppressWarnings("serial")
public class HTTPHeaderDigest extends HTTPHeader {

	/** The message body content document */
	private final DSSDocument messageBodyDocument;

	/**
	 * The default constructor
	 *
	 * @param messageBodyDocument {@link DSSDocument} the signing message body document content
	 * @param digestAlgorithm {@link DigestAlgorithm} to use to compute the document's Digest element
	 */
	public HTTPHeaderDigest(final DSSDocument messageBodyDocument, final DigestAlgorithm digestAlgorithm) {
		super(DSSJsonUtils.HTTP_HEADER_DIGEST, buildInstanceDigestValue(messageBodyDocument, digestAlgorithm));
		this.messageBodyDocument = messageBodyDocument;
	}
	
	private static String buildInstanceDigestValue(DSSDocument document, DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(document, "DSSDocument shall be provided!");
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm shall be provided!");
		
		String jwsHttpHeaderAlgo = digestAlgorithm.getHttpHeaderAlgo();
		if (jwsHttpHeaderAlgo == null) {
			throw new IllegalArgumentException(String.format("The DigestAlgorithm '%s' is not supported for 'sigD' HTTP_HEADERS mechanism. "
					+ "See RFC 5843 for more information.", digestAlgorithm));
		}
		/*
		 * RFC 3230 "Instance Digests in HTTP"
		 * 
		 * 4.2 Instance digests
		 * 
		 * An instance digest is the representation of the output of a digest
		 * algorithm, together with an indication of the algorithm used (and any
		 * parameters).
		 * 
		 * instance-digest = digest-algorithm "="
		 *                       <encoded digest output>
		 */
		
		StringBuilder stringBuilder = new StringBuilder(jwsHttpHeaderAlgo);
		stringBuilder.append("=");
		
		String digest = document.getDigest(digestAlgorithm);
		stringBuilder.append(digest);
		
		return stringBuilder.toString();
	}

	/**
	 * Returns the original HTTP Message Body Document
	 * 
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getMessageBodyDocument() {
		return messageBodyDocument;
	}

}
