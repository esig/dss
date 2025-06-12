/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509.revocation.crl;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CRLTokenTest {

	@Test
	void testOK() throws IOException {
		FileDocument doc = new FileDocument("src/test/resources/crl/belgium2.crl");
		FileDocument caCert = new FileDocument("src/test/resources/belgiumrs2.crt");
		FileDocument tsaCert = new FileDocument("src/test/resources/TSA_BE.cer");

		CRLBinary crlBinary = CRLUtils.buildCRLBinary(DSSUtils.toByteArray(doc));
		CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, DSSUtils.loadCertificate(caCert.openStream()));
		assertNotNull(crlValidity);
		assertTrue(crlValidity.isSignatureIntact());
		assertTrue(crlValidity.isCrlSignKeyUsage());
		assertTrue(crlValidity.isIssuerX509PrincipalMatches());

		CRLToken crl = new CRLToken(DSSUtils.loadCertificate(tsaCert.openStream()), crlValidity);
		assertNotNull(crl);
		assertNotNull(crl.getAbbreviation());
		assertNotNull(crl.getCreationDate());
		assertNotNull(crl.getCrlValidity());
		assertNotNull(crl.getDSSId());
		assertNotNull(crl.getIssuerX500Principal());
		assertNotNull(crl.getPublicKeyOfTheSigner());
		assertNotNull(crl.toString());

		assertEquals(crlValidity.getExpiredCertsOnCRL(), crl.getExpiredCertsOnCRL());

		assertFalse(crl.isCertHashPresent());
		assertNull(crl.getArchiveCutOff());

		assertNull(crl.getCertificateSource());
		assertTrue(Utils.isCollectionEmpty(crl.getCertificates()));
	}

	@Test
	void wrongCRLIssuer() throws IOException {
		FileDocument doc = new FileDocument("src/test/resources/crl/belgium2.crl");
		FileDocument tsaCertFile = new FileDocument("src/test/resources/TSA_BE.cer");

		CRLBinary crlBinary = CRLUtils.buildCRLBinary(DSSUtils.toByteArray(doc));
		CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, DSSUtils.loadCertificate(tsaCertFile.openStream()));
		assertNotNull(crlValidity);
		assertFalse(crlValidity.isSignatureIntact());
		assertFalse(crlValidity.isCrlSignKeyUsage());
		assertFalse(crlValidity.isIssuerX509PrincipalMatches());

		CertificateToken tsaCert = DSSUtils.loadCertificate(tsaCertFile.openStream());
		assertThrows(DSSException.class, () -> new CRLToken(tsaCert, crlValidity));
	}

	@Test
	void wrongCertIssuer() throws IOException {
		FileDocument doc = new FileDocument("src/test/resources/crl/belgium2.crl");
		FileDocument caCertFile = new FileDocument("src/test/resources/belgiumrs2.crt");

		CRLBinary crlBinary = CRLUtils.buildCRLBinary(DSSUtils.toByteArray(doc));
		CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, DSSUtils.loadCertificate(caCertFile.openStream()));
		assertNotNull(crlValidity);
		assertTrue(crlValidity.isSignatureIntact());
		assertTrue(crlValidity.isCrlSignKeyUsage());
		assertTrue(crlValidity.isIssuerX509PrincipalMatches());

		CertificateToken caCert = DSSUtils.loadCertificate(caCertFile.openStream());
		assertThrows(DSSException.class, () -> new CRLToken(caCert, crlValidity));
	}

}
