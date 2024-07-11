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

import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CommonTrustedCertificateSourceTest {

	@Test
	void importKeyStore() throws IOException {
		CommonTrustedCertificateSource ctcs = new CommonTrustedCertificateSource();

		KeyStoreCertificateSource keyStore = new KeyStoreCertificateSource("src/test/resources/keystore.jks", "JKS", "dss-password".toCharArray());
		ctcs.importAsTrusted(keyStore);

		List<CertificateToken> certificates = ctcs.getCertificates();
		assertTrue(Utils.isCollectionNotEmpty(certificates));
		for (CertificateToken certificateToken : certificates) {
			assertEquals(SignatureValidity.NOT_EVALUATED, certificateToken.getSignatureValidity());
		}
	}

}
