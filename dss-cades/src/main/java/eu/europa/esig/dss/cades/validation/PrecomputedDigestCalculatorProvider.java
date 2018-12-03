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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class allows to provide digest values without original document
 */
public class PrecomputedDigestCalculatorProvider implements DigestCalculatorProvider {

	private final DigestDocument digestDocument;

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
				return Utils.fromBase64(digestBase64);
			}

			@Override
			public AlgorithmIdentifier getAlgorithmIdentifier() {
				return digestAlgorithmIdentifier;
			}

		};
	}

}
