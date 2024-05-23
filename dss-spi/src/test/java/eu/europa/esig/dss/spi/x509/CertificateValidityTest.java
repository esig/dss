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

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateValidityTest {
	
	private static CertificateToken certificateToken;
	
	@BeforeAll
	public static void init() {
		certificateToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIC9TCCAd2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADArMQswCQYDVQQGEwJBQTEMMAoGA1UEChMDRFNTMQ4wDAYDVQQDEwVJQ"
				+ "0EgQTAeFw0xMzEyMDIxNzMzMTBaFw0xNTEyMDIxNzMzMTBaMDAxCzAJBgNVBAYTAkFBMQwwCgYDVQQKEwNEU1MxEzARBgNV"
				+ "BAMTCnVzZXIgQSBSU0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJUHHAphmSDdQ1t62tppK+dLTANsE2nAj+HCpas"
				+ "S3ohlBsrhteRsvTAbrDyIzCmTYWu/nVI4TGvbzBESwV/QitlkoMLpYFw32MIBf2DLmECzGJ3vm5haw6u8S9quR1h8Vu7QWd"
				+ "+5KMabZuR+j91RiSuoY0xS2ZQxJw1vhvW9hRYjAgMBAAGjgaIwgZ8wCQYDVR0TBAIwADAdBgNVHQ4EFgQU9ESnTWfwg13c3"
				+ "LQZzqqwibY5WVYwUwYDVR0jBEwwSoAUIO1CDsBSUcEoFZxKaWf1PAL1U+uhL6QtMCsxDDAKBgNVBAoTA0RTUzELMAkGA1UE"
				+ "BhMCQUExDjAMBgNVBAMTBVJDQSBBggEBMAsGA1UdDwQEAwIHgDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEFBQA"
				+ "DggEBAGnhhnoyVUhDnr/BSbZ/uWfSuwzFPG+2V9K6WxdIaaXOORFGIdFwGlAwA/Qzpq9snfBxuTkAykxq0uEDhHTj0qXxWR"
				+ "jQ+Dop/DrmccoF/zDvgGusyY1YXaABd/kc3IYt7ns7z3tpiqIz4A7a/UHplBRXfqjyaZurZuJQRaSdxh6CNhdEUiUBxkbb1"
				+ "SdMjuOgjzSDjcDjcegjvDquMKdDetvtu2Qh4ConBBo3fUImwiFRWnbudS5H2HE18ikC7gY/QIuNr7USf1PNyUgcG2g31cMt"
				+ "emj7UTBHZ2V/jPf7ZXqwfnVSaYkNvM3weAI6R3PI0STjdxN6a9qjt9xld40YEdw=");
	}
	
	@Test
	public void test() {
		CertificateValidity certificateValidity = new CertificateValidity(certificateToken);
		assertFalse(certificateValidity.isValid());
		
		assertFalse(certificateValidity.isIssuerSerialPresent());
		certificateValidity.setIssuerSerialPresent(true);
		assertTrue(certificateValidity.isIssuerSerialPresent());

		assertFalse(certificateValidity.isDigestEqual());
		certificateValidity.setDigestEqual(true);
		assertTrue(certificateValidity.isDigestEqual());

		assertFalse(certificateValidity.isDigestPresent());
		certificateValidity.setDigestPresent(true);
		assertTrue(certificateValidity.isDigestPresent());

		assertFalse(certificateValidity.isDistinguishedNameEqual());
		certificateValidity.setDistinguishedNameEqual(true);
		assertTrue(certificateValidity.isDistinguishedNameEqual());

		assertFalse(certificateValidity.isSerialNumberEqual());
		certificateValidity.setSerialNumberEqual(true);
		assertTrue(certificateValidity.isSerialNumberEqual());

		assertFalse(certificateValidity.isSignerIdMatch());
		certificateValidity.setSignerIdMatch(true);
		assertTrue(certificateValidity.isSignerIdMatch());

		assertTrue(certificateValidity.isValid());
	}
	
	@Test
	public void validityTest() {
		PublicKey publicKey = certificateToken.getPublicKey();
		CertificateValidity certificateValidity = new CertificateValidity(publicKey);
		assertFalse(certificateValidity.isValid());
		
		certificateValidity.setDigestEqual(true);
		assertTrue(certificateValidity.isValid());
		
		certificateValidity.setDigestEqual(false);
		certificateValidity.setDistinguishedNameEqual(true);
		assertFalse(certificateValidity.isValid());
		
		certificateValidity.setSerialNumberEqual(true);
		assertTrue(certificateValidity.isValid());

		certificateValidity.setDistinguishedNameEqual(false);
		certificateValidity.setDigestEqual(true);
		assertTrue(certificateValidity.isValid());
	}
	
	@Test
	public void nullCertificateTokenTest() {
		Exception exception = assertThrows(NullPointerException.class, () -> new CertificateValidity((CertificateToken) null));
		assertEquals("CertificateToken cannot be null!", exception.getMessage());
	}
	
	@Test
	public void nullPublicKeyTest() {
		Exception exception = assertThrows(NullPointerException.class, () -> new CertificateValidity((PublicKey) null));
		assertEquals("PublicKey cannot be null!", exception.getMessage());
	}

}
