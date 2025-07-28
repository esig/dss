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
package eu.europa.esig.dss.service.ocsp;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.OnlineSourceTest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.Calendar;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class FileCacheOCSPSourceTest extends OnlineSourceTest {

	@TempDir
	Path tempDir;

	private FileCacheOCSPSource ocspSource;

	@BeforeEach
	void setUp() {
		File cacheDirectory = tempDir.toFile();
		ocspSource = new FileCacheOCSPSource(cacheDirectory);
	}

	@Test
	void test() {
		OCSPToken revocationToken;

		CertificateToken certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		CertificateToken rootToken = DSSUtils.loadCertificate(new File("src/test/resources/CALT.crt"));
		revocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNull(revocationToken);

		OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
		ocspSource.setProxySource(onlineOCSPSource);
		ocspSource.setDefaultNextUpdateDelay(180L); // cache expiration in 180 seconds
		revocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(revocationToken);
		assertEquals(RevocationOrigin.EXTERNAL, revocationToken.getExternalOrigin());

		// check real findRevocation() method behavior
		OCSPToken savedRevocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(savedRevocationToken);
		assertEquals(revocationToken.getAbbreviation(), savedRevocationToken.getAbbreviation());
		assertEquals(revocationToken.getCreationDate(), savedRevocationToken.getCreationDate());
		assertEquals(revocationToken.getDSSIdAsString(), savedRevocationToken.getDSSIdAsString());
		assertArrayEquals(revocationToken.getEncoded(), savedRevocationToken.getEncoded());
		assertArrayEquals(revocationToken.getIssuerX500Principal().getEncoded(),
				savedRevocationToken.getIssuerX500Principal().getEncoded());
		assertEquals(revocationToken.getNextUpdate(), savedRevocationToken.getNextUpdate());
		assertEquals(RevocationOrigin.CACHED, savedRevocationToken.getExternalOrigin());
		assertNotEquals(revocationToken.getExternalOrigin(), savedRevocationToken.getExternalOrigin());
		assertEquals(revocationToken.getProductionDate(), savedRevocationToken.getProductionDate());
		assertArrayEquals(revocationToken.getPublicKeyOfTheSigner().getEncoded(),
				savedRevocationToken.getPublicKeyOfTheSigner().getEncoded());
		assertEquals(revocationToken.getReason(), savedRevocationToken.getReason());
		assertEquals(revocationToken.getRelatedCertificateId(), savedRevocationToken.getRelatedCertificateId());
		assertEquals(revocationToken.getRevocationDate(), savedRevocationToken.getRevocationDate());
		assertEquals(revocationToken.getSignatureAlgorithm().getEncryptionAlgorithm().name(),
				savedRevocationToken.getSignatureAlgorithm().getEncryptionAlgorithm().name());
		assertEquals(revocationToken.getSourceURL(), savedRevocationToken.getSourceURL());
		assertEquals(revocationToken.getStatus(), savedRevocationToken.getStatus());
		assertEquals(revocationToken.getThisUpdate(), savedRevocationToken.getThisUpdate());

		// check that token can be obtained more than once
		OCSPToken storedRevocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(storedRevocationToken);
		assertEquals(RevocationOrigin.CACHED, storedRevocationToken.getExternalOrigin());

		// check a dummy token with the old maxUpdateDelay
		OCSPToken refreshedRevocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(refreshedRevocationToken);
		assertEquals(RevocationOrigin.CACHED, refreshedRevocationToken.getExternalOrigin());

		// Force refresh (1 second)
		ocspSource.setMaxNextUpdateDelay(1L);

		// wait one second
		Calendar nextSecond = Calendar.getInstance();
		nextSecond.setTime(refreshedRevocationToken.getThisUpdate());
		nextSecond.add(Calendar.SECOND, 1);
		await().atMost(2, TimeUnit.SECONDS).until(() -> Calendar.getInstance().getTime().after(nextSecond.getTime()));

		// check the dummy token with forcing one second refresh
		refreshedRevocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(refreshedRevocationToken);
		assertEquals(RevocationOrigin.EXTERNAL, refreshedRevocationToken.getExternalOrigin());
	}

	@AfterEach
	void cleanUp() {
		if (ocspSource != null) {
			ocspSource.clearCache();
		}
	}

}
