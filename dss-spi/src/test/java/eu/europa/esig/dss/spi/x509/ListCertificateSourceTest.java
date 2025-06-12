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

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ListCertificateSourceTest {

	private static final CertificateToken CERT = DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer"));

	private static final CertificateToken CA_CERT = DSSUtils.loadCertificate(new File("src/test/resources/CZ_CA.cer"));
	
	@Test
	void testReflection() {
		ListCertificateSource ccv = new ListCertificateSource();
		ccv.add(new CommonTrustedCertificateSource());
		
		List<CertificateSource> sources = ccv.getSources();

		CommonCertificateSource commonCertificateSource = new CommonCertificateSource();
		assertThrows(UnsupportedOperationException.class, () -> sources.add(commonCertificateSource));
		
		assertThrows(UnsupportedOperationException.class, sources::clear);
	}

	@Test
	void multipleCertSourcesTest() {
		ListCertificateSource lcs = new ListCertificateSource();

		CommonCertificateSource commonCertificateSource = new CommonCertificateSource();
		commonCertificateSource.addCertificate(CERT);
		assertTrue(lcs.add(commonCertificateSource));

		assertEquals(1, lcs.getNumberOfSources());
		assertEquals(1, lcs.getCertificates().size());

		CommonCertificateSource commonCertificateSourceTwo = new CommonCertificateSource();
		commonCertificateSourceTwo.addCertificate(CERT);
		assertTrue(lcs.add(commonCertificateSourceTwo));

		assertEquals(2, lcs.getNumberOfSources());
		assertEquals(1, lcs.getCertificates().size());

		commonCertificateSourceTwo.addCertificate(CA_CERT);
		assertEquals(2, lcs.getNumberOfSources());
		assertEquals(2, lcs.getCertificates().size());

		commonCertificateSourceTwo.addCertificate(CA_CERT);
		assertEquals(2, lcs.getNumberOfSources());
		assertEquals(2, lcs.getCertificates().size());

		assertTrue(lcs.add(new CommonTrustedCertificateSource()));
		assertEquals(3, lcs.getNumberOfSources());
		assertEquals(2, lcs.getCertificates().size());

		assertTrue(lcs.add(new CommonTrustedCertificateSource()));
		assertEquals(4, lcs.getNumberOfSources());

		assertFalse(lcs.add(commonCertificateSource));
		assertFalse(lcs.add(commonCertificateSourceTwo));
		assertEquals(4, lcs.getNumberOfSources());
	}

}
