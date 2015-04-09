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
package eu.europa.esig.dss.test.gen;

import static org.junit.Assert.assertNotNull;

import java.security.SignatureException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tsp.TSPUtil;
import org.junit.Test;

import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateServiceTest {

	private CertificateService service = new CertificateService();

	@Test
	public void isSelfSigned() throws Exception {
		DSSPrivateKeyEntry entry = service.generateSelfSignedCertificate(SignatureAlgorithm.RSA_SHA256);

		CertificateToken certificate = entry.getCertificate();
		certificate.isSignedBy(certificate);
	}

	@Test(expected = SignatureException.class)
	public void isChildCertificateNotSelfSigned() throws Exception {
		DSSPrivateKeyEntry entryChain = service.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		// Child certificate is signed with the issuer's private key
		CertificateToken token = entryChain.getCertificate();
		X509Certificate certificate = token.getCertificate();
		certificate.verify(token.getPublicKey());
	}

	@Test
	public void generateTspCertificate() throws Exception {
		DSSPrivateKeyEntry keyEntry = service.generateTspCertificate(SignatureAlgorithm.RSA_SHA256);
		assertNotNull(keyEntry);
		CertificateToken certificate = keyEntry.getCertificate();
		TSPUtil.validateCertificate(new X509CertificateHolder(certificate.getEncoded()));
	}
}