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
package eu.europa.esig.dss.cades.signature;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import eu.europa.esig.dss.DSSUtils;

/**
 * ContentSigner using a provided pre-computed signature
 *
 *
 */

public class CustomContentSigner implements ContentSigner {

    private byte[] preComputedSignature;
    private final AlgorithmIdentifier algorithmIdentifier;

    private ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();

	/**
	 * The default constructor for the {@code PreComputedContentSigner}.
	 *
	 * @param algorithmIdentifier
	 */
	public CustomContentSigner(final String algorithmIdentifier) {
		this(algorithmIdentifier, DSSUtils.EMPTY_BYTE_ARRAY);
	}

	/**
	 * This is the constructor for the {@code PreComputedContentSigner} using the real value of the signature.
	 *
	 * @param algorithmIdentifier the JCE algorithm identifier
	 * @param preComputedSignature the preComputedSignature to set
	 */
    public CustomContentSigner(final String algorithmIdentifier, final byte[] preComputedSignature) {

	    this.algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmIdentifier);
        this.preComputedSignature = preComputedSignature;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public ByteArrayOutputStream getOutputStream() {
        return byteOutputStream;
    }

    @Override
    public byte[] getSignature() {
        return preComputedSignature;
    }

}