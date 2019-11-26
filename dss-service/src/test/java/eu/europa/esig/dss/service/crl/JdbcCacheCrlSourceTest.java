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

import java.io.File;
import java.sql.SQLException;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;


public class JdbcCacheCrlSourceTest {
	
	private JdbcDataSource dataSource = new JdbcDataSource();
	
	private JdbcCacheCRLSource crlSource = new JdbcCacheCRLSource();
	
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
		assertEquals(RevocationOrigin.EXTERNAL, revocationToken.getFirstOrigin());

		RevocationToken savedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(savedRevocationToken);
		assertEquals(revocationToken.getRevocationTokenKey(), savedRevocationToken.getRevocationTokenKey());
		assertEquals(revocationToken.getNextUpdate(), savedRevocationToken.getNextUpdate());
		assertEquals(RevocationOrigin.EXTERNAL, savedRevocationToken.getFirstOrigin()); // expired crl
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
		assertEquals(RevocationOrigin.EXTERNAL, revocationToken.getFirstOrigin());
		
		RevocationToken savedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(savedRevocationToken);
		assertEquals(revocationToken.getRevocationTokenKey(), savedRevocationToken.getRevocationTokenKey());
		assertEquals(revocationToken.getNextUpdate(), savedRevocationToken.getNextUpdate());
		assertEquals(RevocationOrigin.CACHED, savedRevocationToken.getFirstOrigin());

		RevocationToken forceRefresh = crlSource.getRevocationToken(certificateToken, caToken, true);
		assertNotNull(forceRefresh);
		assertEquals(RevocationOrigin.EXTERNAL, forceRefresh.getFirstOrigin());

		savedRevocationToken = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(savedRevocationToken);
		assertEquals(RevocationOrigin.CACHED, savedRevocationToken.getFirstOrigin());

		crlSource.setMaxNextUpdateDelay(1L);
		Thread.sleep(1000);
		
		forceRefresh = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(forceRefresh);
		assertEquals(RevocationOrigin.EXTERNAL, forceRefresh.getFirstOrigin());

		crlSource.setMaxNextUpdateDelay(null);
		forceRefresh = crlSource.getRevocationToken(certificateToken, caToken);
		assertNotNull(forceRefresh);
		assertEquals(RevocationOrigin.CACHED, forceRefresh.getFirstOrigin());

	}

	@AfterEach
	public void cleanUp() throws SQLException {
		crlSource.destroyTable();
		assertFalse(crlSource.isTableExists());
		// uncomment if webserver is active
		//webServer.stop();
		//webServer.shutdown();
	}

}
