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
package eu.europa.esig.dss.test.mock;

import java.security.Signature;
import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

public class MockSignatureTokenConnection extends AbstractSignatureTokenConnection {

	public MockSignatureTokenConnection() {
	}

	@Override
	public void close() {

	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
		return null;
	}

	@Override
	public byte[] sign(byte[] bytes, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {

		final EncryptionAlgorithm encryptionAlgorithm = keyEntry.getEncryptionAlgorithm();
		LOG.info("Signature algorithm: " + encryptionAlgorithm + "/" + digestAlgorithm);
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
		final String javaSignatureAlgorithm = signatureAlgorithm.getJCEId();

		try {
			final Signature signature = Signature.getInstance(javaSignatureAlgorithm);
			signature.initSign(((MockPrivateKeyEntry)keyEntry).getPrivateKey());
			signature.update(bytes);
			final byte[] signatureValue = signature.sign();
			return signatureValue;
		} catch(Exception e) {
			throw new DSSException(e);
		}
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {
		return null;
	}

}
