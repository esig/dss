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
package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPSource;

public class OCSPCertificateVerifierTest {

	@Test
	public void testKeyHash() {
		CertificateToken toCheckToken = DSSUtils.loadCertificate(new File("src/test/resources/peru_client.cer"));
		CertificateToken caToken = DSSUtils.loadCertificate(new File("src/test/resources/peru_CA.cer"));
		assertTrue(toCheckToken.isSignedBy(caToken));

		OCSPSource ocspSource = new ExternalResourcesOCSPSource("/peru_ocsp.bin");
		CertificatePool validationCertPool = new CertificatePool();
		validationCertPool.getInstance(toCheckToken, CertificateSourceType.OTHER);
		validationCertPool.getInstance(caToken, CertificateSourceType.OTHER);

		OCSPCertificateVerifier ocspVerifier = new OCSPCertificateVerifier(ocspSource, validationCertPool);
		RevocationToken revocationToken = ocspVerifier.check(toCheckToken);
		assertNotNull(revocationToken);
		assertNotNull(revocationToken.getPublicKeyOfTheSigner());
	}

}
