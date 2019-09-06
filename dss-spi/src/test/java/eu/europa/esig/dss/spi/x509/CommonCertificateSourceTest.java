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
package eu.europa.esig.dss.spi.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;

public class CommonCertificateSourceTest {

	private static final CertificateToken CERT = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));

	@Test
	public void emptyCommonCertificateSource() {
		CommonCertificateSource empty = new CommonCertificateSource();
		assertNotNull(empty.getCertificates());
		assertNotNull(empty.getCertificateSourceType());
		assertEquals(0, empty.getNumberOfCertificates());
	}

	@Test
	public void commonCertificateSource() {
		CertificatePool certPool = new CertificatePool();
		CommonCertificateSource ccc = new CommonCertificateSource(certPool);

		CertificateToken adddedCert = ccc.addCertificate(CERT);
		assertEquals(CERT, adddedCert);

		assertNotNull(ccc.getCertificates());
		assertNotNull(ccc.getCertificateSourceType());
		assertEquals(1, ccc.getNumberOfCertificates());
	}

}
