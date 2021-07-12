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

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSSPKUtilsTest {

	@Test
	public void getPublicKeyEncryptionAlgo() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/BA-QC-Wurzel-CA-2_PN.txt"));
		assertEquals(EncryptionAlgorithm.RSA, EncryptionAlgorithm.forKey(certificate.getPublicKey()));
	}

	@Test
	public void getPublicKeyEncryptionAlgoECDSA() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/certificates/ecdsa.cer"));
		assertEquals(EncryptionAlgorithm.ECDSA, EncryptionAlgorithm.forKey(certificate.getPublicKey()));
	}

	@Test
	public void getPublicKeySize() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/BA-QC-Wurzel-CA-2_PN.txt"));
		assertEquals(2048, DSSPKUtils.getPublicKeySize(certificate.getPublicKey()));
		assertEquals("2048", DSSPKUtils.getStringPublicKeySize(certificate.getPublicKey()));
		assertEquals("2048", DSSPKUtils.getStringPublicKeySize(certificate));
	}

	@Test
	public void getPublicKeySizeECDSA() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/certificates/ecdsa.cer"));
		assertEquals(256, DSSPKUtils.getPublicKeySize(certificate.getPublicKey()));
	}

	@Test
	public void getPublicKeySizeSelfSign() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/certificates/belgiumrca2-self-sign.crt"));
		assertEquals(2048, DSSPKUtils.getPublicKeySize(certificate.getPublicKey()));
		assertEquals("2048", DSSPKUtils.getStringPublicKeySize(certificate.getPublicKey()));
		assertEquals("2048", DSSPKUtils.getStringPublicKeySize(certificate));

	}

	@Test
	public void x25519() {
		CertificateToken token = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZXN0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQDDA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJjga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAgBgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cgw1AH9efZBw==");
		assertEquals(EncryptionAlgorithm.X25519, EncryptionAlgorithm.forKey(token.getPublicKey()));
		assertEquals(32, DSSPKUtils.getPublicKeySize(token.getPublicKey()));
		assertTrue(token.checkKeyUsage(KeyUsageBit.KEY_AGREEMENT));
	}

	@Test
	public void Ed25519() {
		CertificateToken token = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIBCDCBuwIUGW78zw0OL0GptJi++a91dBa7DsQwBQYDK2VwMCcxCzAJBgNVBAYTAkRFMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wHhcNMTkwMzMxMTc1MTIyWhcNMjEwMjI4MTc1MTIyWjAnMQswCQYDVQQGEwJERTEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCowBQYDK2VwAyEAK87g0b8CC1eA5mvKXt9uezZwJYWEyg74Y0xTZEkqCcwwBQYDK2VwA0EAIIu/aa3Qtr3IE5to/nvWVY9y3ciwG5DnA70X3ALUhFs+U5aLtfY8sNT1Ng72ht+UBwByuze20UsL9qMsmknQCA==");
		assertNotNull(token);
		assertEquals(EncryptionAlgorithm.EDDSA, EncryptionAlgorithm.forKey(token.getPublicKey()));
		assertEquals(32, DSSPKUtils.getPublicKeySize(token.getPublicKey()));
		assertFalse(token.checkKeyUsage(KeyUsageBit.KEY_AGREEMENT));
	}

}
