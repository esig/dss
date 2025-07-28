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
package eu.europa.esig.dss.service.crl;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.OnlineSourceTest;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.Calendar;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class FileCacheCRLSourceTest extends OnlineSourceTest {

	@TempDir
	Path tempDir;

	private FileCacheCRLSource crlSource;

	@BeforeEach
	void setUp() {
		File cacheDirectory = tempDir.toFile();
		crlSource = new FileCacheCRLSource(cacheDirectory);
	}

	@Test
	void test() {
		CRLToken revocationToken;

		DataLoader dataLoader = new CommonsDataLoader();
		CertificateToken certificateToken = DSSUtils
				.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-user-crl-ocsp.crt"));
		CertificateToken caToken = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-ca.crt"));

		revocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNull(revocationToken);

		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		crlSource.setProxySource(onlineCRLSource);
		revocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(revocationToken);
		assertEquals(RevocationOrigin.EXTERNAL, revocationToken.getExternalOrigin());

		CRLToken savedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(savedRevocationToken);
		compareTokens(revocationToken, savedRevocationToken);
		assertEquals(RevocationOrigin.CACHED, savedRevocationToken.getExternalOrigin());

		CRLToken forceRefresh = crlSource.getRevocationToken(certificateToken, caToken, true);
		assertNotNull(forceRefresh);
		assertEquals(RevocationOrigin.EXTERNAL, forceRefresh.getExternalOrigin());

		savedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(savedRevocationToken);
		compareTokens(forceRefresh, savedRevocationToken);
		assertEquals(RevocationOrigin.CACHED, savedRevocationToken.getExternalOrigin());

		crlSource.setMaxNextUpdateDelay(1L);

		// wait one second
		Calendar nextSecond = Calendar.getInstance();
		nextSecond.setTime(savedRevocationToken.getThisUpdate());
		nextSecond.add(Calendar.SECOND, 1);
		await().atMost(2, TimeUnit.SECONDS).until(() -> Calendar.getInstance().getTime().after(nextSecond.getTime()));

		forceRefresh = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(forceRefresh);
		assertEquals(RevocationOrigin.EXTERNAL, forceRefresh.getExternalOrigin());

		crlSource.setMaxNextUpdateDelay(null);
		forceRefresh = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(forceRefresh);
		assertEquals(RevocationOrigin.CACHED, forceRefresh.getExternalOrigin());

	}

	@Test
	void testExpired() {
		CRLToken revocationToken;

		CertificateToken certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		CertificateToken caToken = DSSUtils.loadCertificate(new File("src/test/resources/CALT.crt"));
		revocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNull(revocationToken);

		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		crlSource.setProxySource(onlineCRLSource);
		revocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(revocationToken);
		assertEquals(RevocationOrigin.EXTERNAL, revocationToken.getExternalOrigin());

		CRLToken savedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(savedRevocationToken);
		assertEquals(revocationToken.getNextUpdate(), savedRevocationToken.getNextUpdate());
		assertEquals(RevocationOrigin.EXTERNAL, savedRevocationToken.getExternalOrigin()); // expired crl
	}

	private void compareTokens(CRLToken originalCRL, CRLToken cachedCRL) {
		assertEquals(originalCRL.getSignatureAlgorithm(), cachedCRL.getSignatureAlgorithm());
		assertEquals(originalCRL.getThisUpdate(), cachedCRL.getThisUpdate());
		assertEquals(originalCRL.getNextUpdate(), cachedCRL.getNextUpdate());
		assertEquals(originalCRL.getExpiredCertsOnCRL(), cachedCRL.getExpiredCertsOnCRL());
		assertEquals(originalCRL.getIssuerCertificateToken(), cachedCRL.getIssuerCertificateToken());
		assertEquals(originalCRL.isSignatureIntact(), cachedCRL.isSignatureIntact());
		assertEquals(originalCRL.isValid(), cachedCRL.isValid());
		assertEquals(originalCRL.isCertHashPresent(), cachedCRL.isCertHashPresent());
		assertEquals(originalCRL.isCertHashMatch(), cachedCRL.isCertHashMatch());
		assertEquals(originalCRL.getSignatureValidity(), cachedCRL.getSignatureValidity());
		assertEquals(originalCRL.getReason(), cachedCRL.getReason());
	}

	@AfterEach
	void cleanUp() {
		if (crlSource != null) {
			crlSource.clearCache();
		}
	}

}
