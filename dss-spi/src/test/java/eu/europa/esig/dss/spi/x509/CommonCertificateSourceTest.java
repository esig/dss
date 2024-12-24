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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CommonCertificateSourceTest {

	private static final CertificateToken CERT = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));

	private static final CertificateToken SAME_PK_CERT_1 = DSSUtils.loadCertificateFromBase64EncodedString(
			"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");
	private static final CertificateToken SAME_PK_CERT_2 = DSSUtils.loadCertificateFromBase64EncodedString(
			"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");
	private static final CertificateToken SAME_PK_CERT_3 = DSSUtils.loadCertificateFromBase64EncodedString(
			"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");

	@Test
	void emptyCommonCertificateSource() {
		CommonCertificateSource empty = new CommonCertificateSource();
		assertNotNull(empty.getCertificates());
		assertNotNull(empty.getCertificateSourceType());
		assertEquals(0, empty.getNumberOfCertificates());
		assertEquals(0, empty.getNumberOfEntities());
		assertFalse(empty.isKnown(CERT));
		assertFalse(empty.isTrusted(CERT));
	}

	@Test
	void commonCertificateSource() {
		CommonCertificateSource ccc = new CommonCertificateSource();
		assertFalse(ccc.isKnown(CERT));
		assertFalse(ccc.isTrusted(CERT));

		CertificateToken addedCert = ccc.addCertificate(CERT);
		assertEquals(CERT, addedCert);

		assertNotNull(ccc.getCertificates());
		assertEquals(CertificateSourceType.OTHER, ccc.getCertificateSourceType());
		assertEquals(1, ccc.getNumberOfCertificates());
		assertEquals(1, ccc.getNumberOfEntities());
		assertTrue(ccc.isKnown(CERT));
		assertFalse(ccc.isTrusted(CERT));

		ccc.reset();
		assertFalse(ccc.isKnown(CERT));
		assertFalse(ccc.isTrusted(CERT));
		assertEquals(0, ccc.getNumberOfCertificates());
		assertEquals(0, ccc.getNumberOfEntities());
	}

	@Test
	void equalityTest() {
		CertificateSource ccOne = new CommonCertificateSource();
		CertificateSource ccTwo = new CommonCertificateSource();
		assertTrue(ccOne.isCertificateSourceEqual(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEqual(ccOne));

		ccOne.addCertificate(CERT);
		assertFalse(ccOne.isCertificateSourceEqual(ccTwo));
		assertFalse(ccTwo.isCertificateSourceEqual(ccOne));

		ccTwo.addCertificate(CERT);
		assertTrue(ccOne.isCertificateSourceEqual(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEqual(ccOne));

		ccOne.addCertificate(CERT);
		assertTrue(ccOne.isCertificateSourceEqual(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEqual(ccOne));

		ccOne.addCertificate(SAME_PK_CERT_1);
		ccTwo.addCertificate(SAME_PK_CERT_2);
		assertFalse(ccOne.isCertificateSourceEqual(ccTwo));
		assertFalse(ccTwo.isCertificateSourceEqual(ccOne));

		ccOne.addCertificate(SAME_PK_CERT_2);
		ccTwo.addCertificate(SAME_PK_CERT_1);
		assertTrue(ccOne.isCertificateSourceEqual(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEqual(ccOne));

		ccOne.addCertificate(SAME_PK_CERT_2);
		assertTrue(ccOne.isCertificateSourceEqual(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEqual(ccOne));
	}

	@Test
	void equivalenceTest() {
		CertificateSource ccOne = new CommonCertificateSource();
		CertificateSource ccTwo = new CommonCertificateSource();
		assertTrue(ccOne.isCertificateSourceEquivalent(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEquivalent(ccOne));

		ccOne.addCertificate(CERT);
		assertFalse(ccOne.isCertificateSourceEquivalent(ccTwo));
		assertFalse(ccTwo.isCertificateSourceEquivalent(ccOne));

		ccTwo.addCertificate(CERT);
		assertTrue(ccOne.isCertificateSourceEquivalent(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEquivalent(ccOne));

		ccOne.addCertificate(CERT);
		assertTrue(ccOne.isCertificateSourceEquivalent(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEquivalent(ccOne));

		ccOne.addCertificate(SAME_PK_CERT_1);
		ccTwo.addCertificate(SAME_PK_CERT_2);
		assertTrue(ccOne.isCertificateSourceEquivalent(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEquivalent(ccOne));

		ccOne.addCertificate(SAME_PK_CERT_2);
		ccTwo.addCertificate(SAME_PK_CERT_1);
		assertTrue(ccOne.isCertificateSourceEquivalent(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEquivalent(ccOne));

		ccOne.addCertificate(SAME_PK_CERT_2);
		assertTrue(ccOne.isCertificateSourceEquivalent(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEquivalent(ccOne));

		ccOne.addCertificate(SAME_PK_CERT_3);
		assertTrue(ccOne.isCertificateSourceEquivalent(ccOne));
		assertFalse(ccOne.isCertificateSourceEquivalent(ccTwo));
		assertFalse(ccTwo.isCertificateSourceEquivalent(ccOne));

		ccTwo.addCertificate(SAME_PK_CERT_3);
		assertTrue(ccOne.isCertificateSourceEquivalent(ccTwo));
		assertTrue(ccTwo.isCertificateSourceEquivalent(ccOne));
	}

}
