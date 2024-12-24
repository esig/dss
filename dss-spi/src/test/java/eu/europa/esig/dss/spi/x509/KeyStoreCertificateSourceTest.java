/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyStoreCertificateSourceTest {

	private static final char[] KEYSTORE_PASSWORD = "dss-password".toCharArray();
	private static final String KEYSTORE_TYPE = "JKS";
	private static final String KEYSTORE_FILEPATH = "src/test/resources/keystore.jks";

	@Test
	void testLoadAddAndDelete() throws IOException {
		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(new File(KEYSTORE_FILEPATH), KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		assertNotNull(kscs);

		int startSize = Utils.collectionSize(kscs.getCertificates());
		assertTrue(startSize > 0);

		CertificateToken token = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		CertificateToken token2 = DSSUtils.loadCertificate(new File("src/test/resources/ecdsa.cer"));
		kscs.addCertificateToKeyStore(token);

		int sizeAfterAdd = Utils.collectionSize(kscs.getCertificates());
		assertEquals(sizeAfterAdd, startSize + 1);

		String tokenId = token.getDSSIdAsString();
		String token2Id = token2.getDSSIdAsString();

		assertNotNull(kscs.getCertificate(tokenId));
		assertNull(kscs.getCertificate(token2Id));
		assertEquals(1, kscs.getByEntityKey(token.getEntityKey()).size());
		assertEquals(1, kscs.getByPublicKey(token.getPublicKey()).size());
		assertEquals(1, kscs.getBySubject(token.getSubject()).size());
		assertEquals(0, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token2.getSubject()).size());

		kscs.deleteCertificateFromKeyStore(tokenId);

		int sizeAfterDelete = Utils.collectionSize(kscs.getCertificates());
		assertEquals(sizeAfterDelete, startSize);

		assertNull(kscs.getCertificate(tokenId));
		assertNull(kscs.getCertificate(token2Id));
		assertEquals(0, kscs.getByEntityKey(token.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token.getSubject()).size());
		assertEquals(0, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token2.getSubject()).size());

		kscs.addAllCertificatesToKeyStore(Arrays.asList(token, token2));

		sizeAfterAdd = Utils.collectionSize(kscs.getCertificates());
		assertEquals(sizeAfterAdd, startSize + 2);

		assertNull(kscs.getCertificate("AAAAAAAAAAAAAAAA"));
		assertNotNull(kscs.getCertificate(tokenId));
		assertNotNull(kscs.getCertificate(token2Id));
		assertEquals(1, kscs.getByEntityKey(token.getEntityKey()).size());
		assertEquals(1, kscs.getByPublicKey(token.getPublicKey()).size());
		assertEquals(1, kscs.getBySubject(token.getSubject()).size());
		assertEquals(1, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(1, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(1, kscs.getBySubject(token2.getSubject()).size());
	}

	@Test
	void loadKeystoreAndTruststore() throws IOException {
		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(new File("src/test/resources/good-user.p12"), "PKCS12", "ks-password".toCharArray());
		assertTrue(kscs.getCertificates().size() > 0);

		kscs = new KeyStoreCertificateSource(new File("src/test/resources/trust-anchors.jks"), "JKS", "ks-password".toCharArray());
		assertTrue(kscs.getCertificates().size() > 0);
	}

	@Test
	void testCreateNewKeystore() throws IOException {
		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		CertificateToken token = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		kscs.addCertificateToKeyStore(token);

		kscs.store(Files.newOutputStream(Paths.get("target/new_keystore.jks")));

		KeyStoreCertificateSource kscs2 = new KeyStoreCertificateSource("target/new_keystore.jks", KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		assertEquals(1, Utils.collectionSize(kscs2.getCertificates()));
	}

	@Test
	void wrongPassword() {
		File ksFile = new File(KEYSTORE_FILEPATH);
		assertThrows(DSSException.class, () -> new KeyStoreCertificateSource(ksFile, KEYSTORE_TYPE, "wrong password".toCharArray()));
	}

	@Test
	void wrongFile() {
		File wrongFile = new File("src/test/resources/keystore.p13");
		assertThrows(IOException.class,
				() -> new KeyStoreCertificateSource(wrongFile, KEYSTORE_TYPE, KEYSTORE_PASSWORD));
	}

	@Test
	void clearAllCertificates() throws IOException {
		String tempJKS = "target/temp.jks";
		Utils.copy(Files.newInputStream(Paths.get(KEYSTORE_FILEPATH)), Files.newOutputStream(Paths.get(tempJKS)));

		File ksFile = new File(tempJKS);
		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(ksFile, KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		List<CertificateToken> originalCertificates = kscs.getCertificates();
		assertTrue(Utils.isCollectionNotEmpty(originalCertificates));
		for (CertificateToken certificateToken : originalCertificates) {
			assertEquals(1, kscs.getByEntityKey(certificateToken.getEntityKey()).size());
			assertEquals(1, kscs.getByPublicKey(certificateToken.getPublicKey()).size());
			assertEquals(1, kscs.getBySubject(certificateToken.getSubject()).size());
		}

		kscs.clearAllCertificates();

		List<CertificateToken> finalCertificates = kscs.getCertificates();
		assertTrue(Utils.isCollectionEmpty(finalCertificates));
		for (CertificateToken certificateToken : originalCertificates) {
			assertEquals(0, kscs.getByEntityKey(certificateToken.getEntityKey()).size());
			assertEquals(0, kscs.getByPublicKey(certificateToken.getPublicKey()).size());
			assertEquals(0, kscs.getBySubject(certificateToken.getSubject()).size());
		}
	}

	@Test
	void addCertificateTest() throws IOException {
		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(new File(KEYSTORE_FILEPATH), KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		assertNotNull(kscs);
		CertificateToken token = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));

		Exception exception = assertThrows(UnsupportedOperationException.class, () -> kscs.addCertificate(token));
		assertEquals("Use addCertificateToKeyStore(CertificateToken) method to add a certificate to keyStore!", exception.getMessage());
	}

	@Test
	void crossCertificatesTest() {
		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		assertEquals(0, kscs.getCertificates().size());

		CertificateToken token1 = DSSUtils.loadCertificateFromBase64EncodedString("MIID+jCCAuKgAwIBAgICB9IwDQYJKoZIhvcNAQENBQAwUTEUMBIGA1UEAwwLZXh0ZXJuYWwtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTAeFw0yMTA3MTMwOTAzMDRaFw0yMzA3MTMwOTAzMDRaMFAxEzARBgNVBAMMCmNjLXJvb3QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ8bZ/5pRH/MNjDDoarDfW0eUqAyiKKCIJAXmdRLkhnYJ6rEy1vshMBV6w7pfq8VpgJ8inMmEGACaJtaOcsxClTb35zu6WZvVX7D7rd3boKk6H0ulIK7cEPxTET/a6Ua+AddIzZaNKyiUDI+VmxfLpNxkcl0xDQQ/hUS34jN/sBNzqnaYU3om2LeuwAod3po2A9AQi2DgO4qna4EaVL6LFrV5SjnZzIlJVS2xShIILGQOj6AbPxBQdmkN1Ls5Cg4Uw3nn+KjHu+FAUhLk445c/ZkIyJ2XYhklJ3KOeoEoY6FsnHbgqc2NPbl8YkmOahdPGfhPZo5Gi2HxdXtnDG/4gkCAwEAAaOB3DCB2TAOBgNVHQ8BAf8EBAMCAQYwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL2V4dGVybmFsLWNhLmNybDBQBggrBgEFBQcBAQREMEIwQAYIKwYBBQUHMAKGNGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9leHRlcm5hbC1jYS5jcnQwHQYDVR0OBBYEFMySSB/cZxx8kr4mBvPVO71ohVkIMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEBABrOJZA9HQffvnk2tmayQW+lm+mHFXHkLGx/ArAe7eUBt68TTgElwaw0UIX/a99jYeEehTBugiZoWYCl1LBPHOPHxVb7Rn8g7mSrlIl1/uvVAAx+D51U9NpK4ThilNhmbwQb4gv1PEVBmtux8i8DdqX5yq2USQNOchiEO+z5EOmWZ8tZAS9cnqrQa84p6dGYZDyM5trFv6mlvJM4kHiK9NW90hUwdzW5nK4y22DXO4ZwOos6wNHDTbCzqBNi5O+45u4UvRgzRZD1RupOBHeHeQsjV0RR19QWjsx2Fvf+0RV6LQBShsphDKvQ5mG3jiov41Eq6EJ0yzVutLtdZhEh8Yg===");
		CertificateToken token2 = DSSUtils.loadCertificateFromBase64EncodedString("MIIDXjCCAkagAwIBAgICB9MwDQYJKoZIhvcNAQENBQAwUDETMBEGA1UEAwwKY2Mtcm9vdC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTIxMDcxMzA5MDMwNFoXDTIzMDcxMzA5MDMwNFowUDETMBEGA1UEAwwKY2Mtcm9vdC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnxtn/mlEf8w2MMOhqsN9bR5SoDKIooIgkBeZ1EuSGdgnqsTLW+yEwFXrDul+rxWmAnyKcyYQYAJom1o5yzEKVNvfnO7pZm9VfsPut3dugqTofS6UgrtwQ/FMRP9rpRr4B10jNlo0rKJQMj5WbF8uk3GRyXTENBD+FRLfiM3+wE3OqdphTeibYt67ACh3emjYD0BCLYOA7iqdrgRpUvosWtXlKOdnMiUlVLbFKEggsZA6PoBs/EFB2aQ3UuzkKDhTDeef4qMe74UBSEuTjjlz9mQjInZdiGSUnco56gShjoWycduCpzY09uXxiSY5qF08Z+E9mjkaLYfF1e2cMb/iCQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMySSB/cZxx8kr4mBvPVO71ohVkIMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEBAE9mfls0XfaEXY6qyFHUH9I4SuyAchFSjJWMuRhhvqROlCMBdGfwXq6DsZSy082tN57Te/CPggPwy2mBpB9Qag5BbxhJj+5vmYChx0C74Yg08dnFo5jQaZtIdxJdkYUFi9TEQOlHa9tGCkDxpDRtjcBSR47Fdz3i9IvMdZHD3GJmCyAEg+R3/wymqKL4kOKfkCKsxCVwqIgKWTTdiR+y98y53FuMZeqrUW+WWCa72sZGk1RuFh2dxabrA5kRZROm93+RiC5FjSrW0eeqPeaAoYGsKMMGqgaMVUtzf3Addf8YdFQ7awhzob5KMeoQa12RePLPExeN9Be2qxEaCUEQvww===");

		assertFalse(kscs.isKnown(token1));
		assertFalse(kscs.isKnown(token2));
		assertEquals(0, kscs.getByEntityKey(token1.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token1.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token1.getSubject()).size());
		assertEquals(0, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token2.getSubject()).size());

		kscs.addCertificateToKeyStore(token1);

		assertTrue(kscs.isKnown(token1));
		assertTrue(kscs.isKnown(token2));
		assertEquals(1, kscs.getByEntityKey(token1.getEntityKey()).size());
		assertEquals(1, kscs.getByPublicKey(token1.getPublicKey()).size());
		assertEquals(1, kscs.getBySubject(token1.getSubject()).size());
		assertEquals(1, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(1, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(1, kscs.getBySubject(token2.getSubject()).size());

		kscs.addCertificateToKeyStore(token2);

		assertTrue(kscs.isKnown(token1));
		assertTrue(kscs.isKnown(token2));
		assertEquals(2, kscs.getByEntityKey(token1.getEntityKey()).size());
		assertEquals(2, kscs.getByPublicKey(token1.getPublicKey()).size());
		assertEquals(2, kscs.getBySubject(token1.getSubject()).size());
		assertEquals(2, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(2, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(2, kscs.getBySubject(token2.getSubject()).size());

		kscs.removeCertificate(token1);

		assertTrue(kscs.isKnown(token1));
		assertTrue(kscs.isKnown(token2));
		assertEquals(1, kscs.getByEntityKey(token1.getEntityKey()).size());
		assertEquals(1, kscs.getByPublicKey(token1.getPublicKey()).size());
		assertEquals(1, kscs.getBySubject(token1.getSubject()).size());
		assertEquals(1, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(1, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(1, kscs.getBySubject(token2.getSubject()).size());

		kscs.removeCertificate(token2);

		assertFalse(kscs.isKnown(token1));
		assertFalse(kscs.isKnown(token2));
		assertEquals(0, kscs.getByEntityKey(token1.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token1.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token1.getSubject()).size());
		assertEquals(0, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token2.getSubject()).size());

		kscs.removeCertificate(token1);
		kscs.removeCertificate(token2);

		assertFalse(kscs.isKnown(token1));
		assertFalse(kscs.isKnown(token2));
		assertEquals(0, kscs.getByEntityKey(token1.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token1.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token1.getSubject()).size());
		assertEquals(0, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token2.getSubject()).size());

		// re-add certificates

		kscs.addCertificateToKeyStore(token2);

		assertTrue(kscs.isKnown(token1));
		assertTrue(kscs.isKnown(token2));
		assertEquals(1, kscs.getByEntityKey(token1.getEntityKey()).size());
		assertEquals(1, kscs.getByPublicKey(token1.getPublicKey()).size());
		assertEquals(1, kscs.getBySubject(token1.getSubject()).size());
		assertEquals(1, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(1, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(1, kscs.getBySubject(token2.getSubject()).size());

		kscs.addCertificateToKeyStore(token1);

		assertTrue(kscs.isKnown(token1));
		assertTrue(kscs.isKnown(token2));
		assertEquals(2, kscs.getByEntityKey(token1.getEntityKey()).size());
		assertEquals(2, kscs.getByPublicKey(token1.getPublicKey()).size());
		assertEquals(2, kscs.getBySubject(token1.getSubject()).size());
		assertEquals(2, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(2, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(2, kscs.getBySubject(token2.getSubject()).size());

		kscs.reset();

		assertFalse(kscs.isKnown(token1));
		assertFalse(kscs.isKnown(token2));
		assertEquals(0, kscs.getByEntityKey(token1.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token1.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token1.getSubject()).size());
		assertEquals(0, kscs.getByEntityKey(token2.getEntityKey()).size());
		assertEquals(0, kscs.getByPublicKey(token2.getPublicKey()).size());
		assertEquals(0, kscs.getBySubject(token2.getSubject()).size());
	}

}
