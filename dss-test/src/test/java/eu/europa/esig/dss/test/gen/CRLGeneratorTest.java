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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Date;

import org.bouncycastle.asn1.x509.CRLReason;
import org.junit.Test;

import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;

public class CRLGeneratorTest {

	private CertificateService certificateService = new CertificateService();
	private CRLGenerator crlGenerator = new CRLGenerator();

	@Test
	public void test() throws Exception {
		MockPrivateKeyEntry issuerKeyEntry = certificateService.generateSelfSignedCertificate(SignatureAlgorithm.RSA_SHA256);
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256, issuerKeyEntry);
		X509CRL generatedCRL = crlGenerator.generateCRL(privateKeyEntry.getCertificate().getCertificate(), issuerKeyEntry, new Date(), CRLReason.privilegeWithdrawn);
		assertNotNull(generatedCRL);

		assertEquals(issuerKeyEntry.getCertificate().getSubjectX500Principal(), generatedCRL.getIssuerX500Principal());

		X509CRLEntry revokedCertificate = generatedCRL.getRevokedCertificate(privateKeyEntry.getCertificate().getSerialNumber());
		assertNotNull(revokedCertificate);
	}

}
