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
package eu.europa.esig.dss.spi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.DigestCalculator;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;

class DSSRevocationUtilsTest {

	@Test
	void testRevocationOCSP() throws IOException {
		BasicOCSPResp basicOCSPResp = DSSRevocationUtils.loadOCSPBase64Encoded(
				"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");
		assertNotNull(basicOCSPResp);

		OCSPResp ocspResp = DSSRevocationUtils.fromBasicToResp(basicOCSPResp);
		assertNotNull(ocspResp);

		BasicOCSPResp basicOCSPResp2 = DSSRevocationUtils.fromRespToBasic(ocspResp);
		assertNotNull(basicOCSPResp2);

		assertEquals(basicOCSPResp, basicOCSPResp2);
	}

	@Test
	void testGetOCSPCertificateIDAndMatch() throws IOException {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		CertificateToken issuer = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrs2.crt"));
		assertTrue(certificate.isSignedBy(issuer));

		CertificateID certificateID = DSSRevocationUtils.getOCSPCertificateID(certificate, issuer, DigestAlgorithm.SHA256);
		assertNotNull(certificateID);

		BasicOCSPResp basicOCSPResp = DSSRevocationUtils.loadOCSPBase64Encoded(
				"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");

		SingleResp[] responses = basicOCSPResp.getResponses();

		assertFalse(DSSRevocationUtils.matches(certificateID, responses[0]));
	}

	@Test
	void testWrongOCSP() throws IOException {
		assertThrows(IOException.class, () ->DSSRevocationUtils.loadOCSPBase64Encoded("MIIHOgoBAK"));
	}
	
	@Test
	void getCrlRevocationTokenKeys() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		List<String> revocationKeys = DSSRevocationUtils.getCRLRevocationTokenKeys(certificate);
		assertNotNull(revocationKeys);
		assertFalse(CollectionUtils.isEmpty(revocationKeys));
		assertEquals(1, Utils.collectionSize(revocationKeys));
	}
	
	@Test
	void getOcspRevocationTokenKeys() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		List<String> revocationKeys = DSSRevocationUtils.getOcspRevocationTokenKeys(certificate);
		assertNotNull(revocationKeys);
		assertFalse(CollectionUtils.isEmpty(revocationKeys));
		assertEquals(1, Utils.collectionSize(revocationKeys));
	}
	
	@Test
	void getEmptyCrlRevocationTokenKeys() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/good-user.crt"));
		List<String> revocationKeys = DSSRevocationUtils.getCRLRevocationTokenKeys(certificate);
		assertNotNull(revocationKeys);
		assertTrue(CollectionUtils.isEmpty(revocationKeys));
	}
	
	@Test
	void getEmptyOcspRevocationTokenKeys() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/sk_ca.cer"));
		List<String> revocationKeys = DSSRevocationUtils.getOcspRevocationTokenKeys(certificate);
		assertNotNull(revocationKeys);
		assertTrue(CollectionUtils.isEmpty(revocationKeys));
	}

	@Test
	void getSHA1DigestCalculator() {
		DigestCalculator digestCalculator = DSSRevocationUtils.getDigestCalculator(DigestAlgorithm.SHA1);
		assertNotNull(digestCalculator);
	}

}
