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

import java.security.PrivateKey;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.x509.CertificateToken;

public class MockPrivateKeyEntry implements DSSPrivateKeyEntry {

	private final EncryptionAlgorithm encryptionAlgo;
	private final CertificateToken certificate;
	private final CertificateToken[] certificateChain;
	private final PrivateKey privateKey;

	public MockPrivateKeyEntry(EncryptionAlgorithm encryptionAlgo, CertificateToken certificate, PrivateKey privateKey) {
		this.encryptionAlgo = encryptionAlgo;
		this.certificate = certificate;
		this.privateKey = privateKey;
		this.certificateChain = null;
	}

	public MockPrivateKeyEntry(EncryptionAlgorithm encryptionAlgo, CertificateToken certificate, CertificateToken[] certificateChain,
			PrivateKey privateKey) {
		this.encryptionAlgo = encryptionAlgo;
		this.certificate = certificate;
		this.certificateChain = certificateChain;
		this.privateKey = privateKey;
	}

	@Override
	public CertificateToken getCertificate() {
		return certificate;
	}

	@Override
	public CertificateToken[] getCertificateChain() {
		return certificateChain;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() throws DSSException {
		return encryptionAlgo;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

}
