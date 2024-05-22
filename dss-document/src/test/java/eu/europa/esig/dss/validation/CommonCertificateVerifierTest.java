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

import eu.europa.esig.dss.model.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CommonCertificateVerifierTest {
	
	@Test
	public void testTrustedCertSources() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		ccv.setTrustedCertSources(new CommonTrustedCertificateSource());
		assertEquals(1, ccv.getTrustedCertSources().getNumberOfSources());
		
		ccv.setTrustedCertSources(new CommonTrustedCertificateSource(), new TrustedListsCertificateSource());
		assertEquals(2, ccv.getTrustedCertSources().getNumberOfSources());
		
		ccv.addTrustedCertSources(new CommonTrustedCertificateSource());
		assertEquals(3, ccv.getTrustedCertSources().getNumberOfSources());
	}

	@Test
	public void testNotTrustedCertificateSource() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		CommonCertificateSource commonCertificateSource = new CommonCertificateSource();

		Exception exception = assertThrows(UnsupportedOperationException.class,
				() -> ccv.setTrustedCertSources(commonCertificateSource));
		assertEquals("The certificateSource with type [OTHER] is not allowed in the trustedCertSources. Please, "
				+ "use CertificateSource with a type TRUSTED_STORE or TRUSTED_LIST.", exception.getMessage());
		
		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		exception = assertThrows(UnsupportedOperationException.class,
				() -> ccv.setTrustedCertSources(commonTrustedCertificateSource, commonCertificateSource));
		assertEquals("The certificateSource with type [OTHER] is not allowed in the trustedCertSources. Please, "
				+ "use CertificateSource with a type TRUSTED_STORE or TRUSTED_LIST.", exception.getMessage());
	}
	
	@Test
	public void testAdjunctCertSources() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		ccv.setAdjunctCertSources(new CommonCertificateSource());
		assertEquals(1, ccv.getAdjunctCertSources().getNumberOfSources());
		
		ccv.setAdjunctCertSources(new CommonCertificateSource(), new CommonCertificateSource());
		assertEquals(2, ccv.getAdjunctCertSources().getNumberOfSources());
		
		ccv.addAdjunctCertSources(new CommonCertificateSource());
		assertEquals(3, ccv.getAdjunctCertSources().getNumberOfSources());
	}

	@Test
	public void testNotAdjunctCertificateSource() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		ccv.setAdjunctCertSources(new CommonTrustedCertificateSource());
		assertEquals(1, ccv.getAdjunctCertSources().getNumberOfSources());
		
		ccv.addAdjunctCertSources(new CommonCertificateSource(), new CommonTrustedCertificateSource());
		assertEquals(3, ccv.getAdjunctCertSources().getNumberOfSources());
	}

}

