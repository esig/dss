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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * This class allows to provide digest values without original document
 */
public class PrecomputedDigestCalculatorProvider implements DigestCalculatorProvider {

	/** The signing DigestDocument */
	private final DigestDocument digestDocument;

	/**
	 * The default constructor
	 *
	 * @param digestDocument {@link DigestDocument} to be signed
	 */
	public PrecomputedDigestCalculatorProvider(DigestDocument digestDocument) {
		this.digestDocument = digestDocument;
	}

	@Override
	public DigestCalculator get(final AlgorithmIdentifier digestAlgorithmIdentifier) throws OperatorCreationException {

		ASN1ObjectIdentifier algorithmOid = digestAlgorithmIdentifier.getAlgorithm();
		final String digestBase64 = digestDocument.getDigest(DigestAlgorithm.forOID(algorithmOid.getId()));

		return new DigestCalculator() {

			@Override
			public OutputStream getOutputStream() {
				OutputStream os = new ByteArrayOutputStream();
				try {
					Utils.write(getDigest(), os);
				} catch (IOException e) {
					throw new DSSException("Unable to get outputstream", e);
				}
				return os;
			}

			@Override
			public byte[] getDigest() {
				if (Utils.isBase64Encoded(digestBase64)) {
					return Utils.fromBase64(digestBase64);
				}
				throw new IllegalArgumentException("The DigestDocument digest value shall be base64-encoded!");
			}

			@Override
			public AlgorithmIdentifier getAlgorithmIdentifier() {
				return digestAlgorithmIdentifier;
			}

		};
	}

}
