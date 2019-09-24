package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.PublicKey;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;

public class CertificateValidityTest {
	
	private CertificateToken certificateToken;
	
	@Before
	public void init() {
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
		
		assertFalse(certificateValidity.isAttributePresent());
		certificateValidity.setAttributePresent(true);
		assertTrue(certificateValidity.isAttributePresent());

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
	
	@Test(expected = NullPointerException.class)
	public void nullCertificateTokenTest() {
		new CertificateValidity((CertificateToken) null);
	}
	
	@Test(expected = NullPointerException.class)
	public void nullPublicKeyTest() {
		new CertificateValidity((PublicKey) null);
	}

}
