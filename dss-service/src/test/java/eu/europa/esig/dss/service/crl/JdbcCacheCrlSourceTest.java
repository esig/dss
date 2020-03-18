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
package eu.europa.esig.dss.service.crl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.sql.SQLException;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;


public class JdbcCacheCrlSourceTest {
	
	private static final Logger LOG = LoggerFactory.getLogger(JdbcCacheCrlSourceTest.class);
	
	private JdbcDataSource dataSource = new JdbcDataSource();
	
	private MockJdbcCacheCRLSource crlSource = new MockJdbcCacheCRLSource();
	
//	private Server webServer;
	
	@BeforeEach
	public void setUp() throws SQLException {		
		// for testing purposes. DB view available on http://localhost:8082
		// webServer = Server.createWebServer("-web","-webAllowOthers","-webPort","8082").start();
		dataSource.setUrl("jdbc:h2:mem:test;create=true;DB_CLOSE_DELAY=-1");
		crlSource.setDataSource(dataSource);
		assertFalse(crlSource.isTableExists());
		crlSource.initTable();
		assertTrue(crlSource.isTableExists());
	}
	
	@Test
	public void testExpired() throws SQLException {
		RevocationToken revocationToken = null;

		CertificateToken certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		CertificateToken caToken = DSSUtils.loadCertificate(new File("src/test/resources/CALT.crt"));
		revocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNull(revocationToken);

		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		crlSource.setProxySource(onlineCRLSource);
		revocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(revocationToken);
		assertNotNull(revocationToken.getRevocationTokenKey());
		assertEquals(RevocationOrigin.EXTERNAL, revocationToken.getExternalOrigin());

		RevocationToken savedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(savedRevocationToken);
		assertEquals(revocationToken.getRevocationTokenKey(), savedRevocationToken.getRevocationTokenKey());
		assertEquals(revocationToken.getNextUpdate(), savedRevocationToken.getNextUpdate());
		assertEquals(RevocationOrigin.EXTERNAL, savedRevocationToken.getExternalOrigin()); // expired crl
	}

	@Test
	public void test() throws Exception {
		RevocationToken revocationToken = null;
		
		CertificateToken certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.crt"));
		CertificateToken caToken = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrs2.crt"));
		revocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNull(revocationToken);
		
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		crlSource.setProxySource(onlineCRLSource);
		revocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(revocationToken);
		assertNotNull(revocationToken.getRevocationTokenKey());
		assertEquals(RevocationOrigin.EXTERNAL, revocationToken.getExternalOrigin());
		
		RevocationToken savedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(savedRevocationToken);
		assertEquals(revocationToken.getRevocationTokenKey(), savedRevocationToken.getRevocationTokenKey());
		assertEquals(revocationToken.getNextUpdate(), savedRevocationToken.getNextUpdate());
		assertEquals(RevocationOrigin.CACHED, savedRevocationToken.getExternalOrigin());

		RevocationToken forceRefresh = crlSource.getRevocationToken(certificateToken, caToken, true);
		assertNotNull(forceRefresh);
		assertEquals(RevocationOrigin.EXTERNAL, forceRefresh.getExternalOrigin());

		savedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(savedRevocationToken);
		assertEquals(RevocationOrigin.CACHED, savedRevocationToken.getExternalOrigin());

		crlSource.setMaxNextUpdateDelay(1L);
		Thread.sleep(1000);
		
		forceRefresh = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(forceRefresh);
		assertEquals(RevocationOrigin.EXTERNAL, forceRefresh.getExternalOrigin());

		crlSource.setMaxNextUpdateDelay(null);
		forceRefresh = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(forceRefresh);
		assertEquals(RevocationOrigin.CACHED, forceRefresh.getExternalOrigin());

	}
	
	@Test
	public void signatureAlgorithmTest() {
		CertificateToken certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.crt"));
		CertificateToken caToken = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrs2.crt"));

		crlSource.setProxySource(new OnlineCRLSource());
		CRLToken revocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(revocationToken);
		assertEquals(RevocationOrigin.EXTERNAL, revocationToken.getExternalOrigin());
		crlSource.removeRevocation(revocationToken);
		
		try {
			CRLBinary crlBinary = new CRLBinary(revocationToken.getEncoded());
			CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, caToken);
			CRLToken crlToken = null;
			
			/* Test insertRevocation() */
			for (SignatureAlgorithm signatureAlgorithm : SignatureAlgorithm.values()) {
				crlValidity.setSignatureAlgorithm(signatureAlgorithm);
				crlToken = new CRLToken(certificateToken, crlValidity);
				crlToken.setRevocationTokenKey(revocationToken.getRevocationTokenKey());
				crlSource.insertRevocation(crlToken);
				
				RevocationToken cachedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
				assertEquals(RevocationOrigin.CACHED, cachedRevocationToken.getExternalOrigin());
				assertEquals(signatureAlgorithm, cachedRevocationToken.getSignatureAlgorithm());
				crlSource.removeRevocation(crlToken);
			}
			
			/* Test updateRevocation() */
			crlSource.insertRevocation(crlToken); // to be sure there is an object to be updated
			for (SignatureAlgorithm signatureAlgorithm : SignatureAlgorithm.values()) {
				crlValidity.setSignatureAlgorithm(signatureAlgorithm);
				crlToken = new CRLToken(certificateToken, crlValidity);
				crlToken.setRevocationTokenKey(revocationToken.getRevocationTokenKey());
				crlSource.updateRevocation(crlToken);

				RevocationToken cachedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
				assertEquals(signatureAlgorithm, cachedRevocationToken.getSignatureAlgorithm());
			}
		} catch (Exception e) {
			LOG.error("Failed :", e);
			fail(e.getMessage());
		}
	}

	@AfterEach
	public void cleanUp() throws SQLException {
		crlSource.destroyTable();
		assertFalse(crlSource.isTableExists());
		// uncomment if webserver is active
		//webServer.stop();
		//webServer.shutdown();
	}
	
	@SuppressWarnings("serial")
	private class MockJdbcCacheCRLSource extends JdbcCacheCRLSource {
		
		@Override
		protected void removeRevocation(CRLToken crlToken) {
			super.removeRevocation(crlToken);
		}
		
	}

}
