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
package eu.europa.esig.dss.spi.x509.revocation.crl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;

public class ExternalResourcesCRLSourceTest {

	@Test
	public void testStreams() throws IOException {
		try (InputStream is1 = new FileInputStream("src/test/resources/crl/LTRCA.crl");
				InputStream is2 = new FileInputStream("src/test/resources/crl/LTGRCA.crl")) {
			ExternalResourcesCRLSource source = new ExternalResourcesCRLSource(is1, is2);

			assertEquals(2, source.getAllRevocationBinaries().size());
			Map<EncapsulatedRevocationTokenIdentifier<CRL>, Set<RevocationOrigin>> allRevocationBinariesWithOrigins = source.getAllRevocationBinariesWithOrigins();
			assertEquals(2, allRevocationBinariesWithOrigins.size());
			for (Set<RevocationOrigin> origins : allRevocationBinariesWithOrigins.values()) {
				assertEquals(1, origins.size());
				assertEquals(RevocationOrigin.EXTERNAL, origins.iterator().next());
			}
		}
	}

	@Test
	public void testPaths() {
		ExternalResourcesCRLSource source = new ExternalResourcesCRLSource("/crl/LTRCA.crl", "/crl/LTGRCA.crl");
		assertEquals(2, source.getAllRevocationBinaries().size());
	}

	@Test
	public void noCRL() {
		DSSException exception = assertThrows(DSSException.class, () -> new ExternalResourcesCRLSource("/keystore.jks"));
		assertEquals("Unable to parse the stream (CRL is expected)", exception.getMessage());
	}

}
