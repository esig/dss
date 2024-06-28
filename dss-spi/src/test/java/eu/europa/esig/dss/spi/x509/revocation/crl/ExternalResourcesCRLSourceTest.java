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

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

class ExternalResourcesCRLSourceTest {

	@Test
	void testStreams() throws IOException {
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
	void testPaths() {
		ExternalResourcesCRLSource source = new ExternalResourcesCRLSource("/crl/LTRCA.crl", "/crl/LTGRCA.crl");
		assertEquals(2, source.getAllRevocationBinaries().size());
	}

	@Test
	void testDSSDocuments() throws IOException {
		DSSDocument crl1 = new FileDocument("src/test/resources/crl/LTRCA.crl");
		DSSDocument crl2 = new FileDocument("src/test/resources/crl/LTGRCA.crl");
		ExternalResourcesCRLSource source = new ExternalResourcesCRLSource(crl1, crl2);

		assertEquals(2, source.getAllRevocationBinaries().size());
		Map<EncapsulatedRevocationTokenIdentifier<CRL>, Set<RevocationOrigin>> allRevocationBinariesWithOrigins = source.getAllRevocationBinariesWithOrigins();
		assertEquals(2, allRevocationBinariesWithOrigins.size());
		for (Set<RevocationOrigin> origins : allRevocationBinariesWithOrigins.values()) {
			assertEquals(1, origins.size());
			assertEquals(RevocationOrigin.EXTERNAL, origins.iterator().next());
		}
	}

	@Test
	void noCRL() {
		DSSException exception = assertThrows(DSSException.class, () -> new ExternalResourcesCRLSource("/keystore.jks"));
		assertEquals("Unable to parse the stream (CRL is expected)", exception.getMessage());
	}

	@Test
	void testWithMultipleCRLTokens() {
		CertificateToken certToken = DSSUtils.loadCertificateFromBase64EncodedString("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");
		CertificateToken caToken = DSSUtils.loadCertificateFromBase64EncodedString("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");

		String crlOneBinaries = "MIIDBDCB7QIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJMVTEWMBQGA1UECgwNTHV4VHJ1c3QgUy5BLjEnMCUGA1UEAwweTHV4VHJ1c3QgR2xvYmFsIFF1YWxpZmllZCBDQSAzFw0yMDA0MDkwMTQ5MTlaFw0yMDA0MDkwNjE5MTlaoGswaTA5BgNVHRwBAf8ELzAtoCugKYYnaHR0cDovL2NybC5sdXh0cnVzdC5sdS9MVEdRQ0EzLU9DU1AuY3JsMAsGA1UdFAQEAgI68zAfBgNVHSMEGDAWgBRjj8KLA7GrjthTR5Ydmah99qyodTANBgkqhkiG9w0BAQsFAAOCAgEArcklkxZZ406e2ZwSHnovB1sP9qtWA+EkPnFQLVKS9ek1OT/7pXxZXjze83KJGTQ583DXUwPGkAzc3pSVaqxTgutLQQkJGTPXgKSWX058C0Wj89jFwytsNWzpXTTnCE6bjC4XmTrgPGvNZcndk3nzAuA4b6yb2/ssDIyrPoC2jPzTE7WX+kbedcKVU7XUvOXwlFlB8gZPxvZp8fiSiSMOZYACEikRVM1n/EtGVEilKDGpsVpkipu6FyCdqohU5BV6shokp45YsbNHudEoJZjzl/fhd/N9QRtn5Cu19bWEASYWA95kj/FJeuuogSwLF6XUtx3ir/HMjEwnLRzZNFT4T7x+0b5KeOHS+SHedyZYJ7O82CRFVlHPiVGIRGIAipwPhmWqXmOPRYKaIyzhOekmWV7c7sRat48Rra/7u8YS6bDD0dZ+Ci/ibfRNcXi/vJQNyFZA/dClgNj/f9ffRZJaMAkzprthX7UGC9zA68Lpga+nOwrGU+tk+0xkSp/tu1g0CbwTtWe4F5Smezmp1MbC13b5HsMft5nAYQ3O6FSBirjtWd26mKmD5KT0Xf0rq8BPCbRMoppxKuZX9g02LWD531ysfCs8VOeSQaJQrO1VbTtszzMbRSPtybIcJZIGpUK/MGoxlCqRWfjlU4T9Fi6GxkD9qZIt0/JCyN3CseMLH4c=";
		String crlTwoBinaries = "MIIDBDCB7QIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJMVTEWMBQGA1UECgwNTHV4VHJ1c3QgUy5BLjEnMCUGA1UEAwweTHV4VHJ1c3QgR2xvYmFsIFF1YWxpZmllZCBDQSAzFw0yMDEyMDExMDQ5MTlaFw0yMDEyMDExNTE5MTlaoGswaTA5BgNVHRwBAf8ELzAtoCugKYYnaHR0cDovL2NybC5sdXh0cnVzdC5sdS9MVEdRQ0EzLU9DU1AuY3JsMAsGA1UdFAQEAgJRHDAfBgNVHSMEGDAWgBRjj8KLA7GrjthTR5Ydmah99qyodTANBgkqhkiG9w0BAQsFAAOCAgEAZMIbooH1SG/p/tSV3piu4Nj232pUApJ0r3iAMC1JwTB0dTEofKZis4ZUMUhDCaC4BZLnDVq12/ieQt3fgsIYNH76C7k75Epphrm58783Z+KJZyLAz8EnsDJlpZLYnmS+gL39WQ9eYulCftjmN7Ht2g2+yJW0Ts5ypOvcyqyWaj9BJDN/qlz8x+SIJ1O0mZ5Poi3oiW39DxCdlExWqvILyV2NhZbU+AhwbJ9ShCIuDIunKHzDLDnibfJUBTIZbxPviaC0KF6px0T/BiAQiQGYR2bEEGKBozauGjmNoRI3zA9CODWByx3A0bfPU50K/KJkAUzCe2ID/wskc2BTRhIBrujOc4d5kuiVEq6K5XWrr3Ppc4tZF9pKa5EOYwJaDKe4SWVlHRwMXaW02V++V/MCL2mw2ciqMiZCHGHAV5S0KTyBdXUuDRQSQkxKigfa/FiqpiNzxHfQblXaomaD3FUEJVdLJ+qIZ49Cq47BvH+hvKC32bHCQmy4EHlaE0ISTOdoKSAgPMxmDtAXa7/LQiQjV67pLl6w7Fanei9bIfLyOJn9HXiS0QNbJseqdAkSjd9gPLnVl50oh+jzn3x4h3LDN7+CozO4uGD2hV4QaSkYPXiJYdF9bN2b1v1F1LxKSOdYeMzqjuEEIWBrnIGPIYM+3XBBy+PkVuvdfuigJPcXGHg=";

		ExternalResourcesCRLSource crlSource = null;
		try (InputStream baisOneCrl = new ByteArrayInputStream(Utils.fromBase64(crlOneBinaries));
			 InputStream baisTwoCrl = new ByteArrayInputStream(Utils.fromBase64(crlTwoBinaries))) {
			crlSource = new ExternalResourcesCRLSource(baisOneCrl, baisTwoCrl);
		} catch (IOException e) {
			fail(e);
		}
		assertNotNull(crlSource);

		List<RevocationToken<CRL>> revocationTokens = crlSource.getRevocationTokens(certToken, caToken);
		assertEquals(2, revocationTokens.size());

		RevocationToken<CRL> lastRevocationToken = crlSource.getRevocationToken(certToken, caToken);
		assertArrayEquals(Utils.fromBase64(crlTwoBinaries), lastRevocationToken.getEncoded());

		// change order

		try (InputStream baisOneCrl = new ByteArrayInputStream(Utils.fromBase64(crlOneBinaries));
			 InputStream baisTwoCrl = new ByteArrayInputStream(Utils.fromBase64(crlTwoBinaries))) {
			crlSource = new ExternalResourcesCRLSource(baisTwoCrl, baisOneCrl);
		} catch (IOException e) {
			fail(e);
		}
		assertNotNull(crlSource);

		revocationTokens = crlSource.getRevocationTokens(certToken, caToken);
		assertEquals(2, revocationTokens.size());

		lastRevocationToken = crlSource.getRevocationToken(certToken, caToken);
		assertArrayEquals(Utils.fromBase64(crlTwoBinaries), lastRevocationToken.getEncoded());
	}

}
