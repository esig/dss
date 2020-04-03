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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

public class CommonCertificateVerifierTest {

	@Test
	public void testNotTrustedCertificateSource() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		Exception exception = assertThrows(DSSException.class, () -> {
			ccv.setTrustedCertSource(new CommonCertificateSource());
		});
		assertEquals("The certificateSource with type [OTHER] is not allowed in the trustedCertSources. Please, "
				+ "use CertificateSource with a type TRUSTED_STORE or TRUSTED_LIST.", exception.getMessage());
		
		exception = assertThrows(DSSException.class, () -> {
			ccv.setTrustedCertSources(new CommonTrustedCertificateSource(), new CommonCertificateSource());
		});
		assertEquals("The certificateSource with type [OTHER] is not allowed in the trustedCertSources. Please, "
				+ "use CertificateSource with a type TRUSTED_STORE or TRUSTED_LIST.", exception.getMessage());
	}
	
	@Test
	public void testReflection() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		ccv.setTrustedCertSource(new CommonTrustedCertificateSource());
		assertThrows(UnsupportedOperationException.class, () -> {
			ccv.getTrustedCertSources().add(new CommonCertificateSource());
		});
		
		assertThrows(UnsupportedOperationException.class, () -> {
			ccv.getTrustedCertSources().clear();
		});
	}
	
	@Test
	public void testClearTrustedCertSources() {
		CommonCertificateVerifier ccv = new CommonCertificateVerifier();
		ccv.setTrustedCertSource(new CommonTrustedCertificateSource());
		assertEquals(1, ccv.getTrustedCertSources().size());
		
		ccv.clearTrustedCertSources();
		assertEquals(0, ccv.getTrustedCertSources().size());
		
		ccv.setTrustedCertSources(new CommonTrustedCertificateSource(), new TrustedListsCertificateSource());
		assertEquals(2, ccv.getTrustedCertSources().size());
	}

}

