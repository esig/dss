package eu.europa.esig.dss.client.revocation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.sql.SQLException;

import org.h2.jdbcx.JdbcDataSource;
import org.h2.tools.Server;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;


public class JdbcCacheCrlSourceTest {
	
	private JdbcDataSource dataSource = new JdbcDataSource();
	
	private JdbcCacheCRLSource crlSource = new JdbcCacheCRLSource();
	
	private Server webServer;
	
	@Before
	public void setUp() throws SQLException {		
		// for testing purposes. DB view available on http://localhost:8082
		// webServer = Server.createWebServer("-web","-webAllowOthers","-webPort","8082").start();
		dataSource.setUrl("jdbc:h2:mem:test;create=true;DB_CLOSE_DELAY=-1");
		crlSource.setDataSource(dataSource);
		crlSource.initTable();
	}
	
	@Test
	public void test() throws SQLException {
		RevocationToken revocationToken = null;
		
		CertificateToken certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		CertificateToken rootToken = DSSUtils.loadCertificate(new File("src/test/resources/CALT.crt"));
		revocationToken = crlSource.getRevocationToken(certificateToken, rootToken);
		assertNull(revocationToken);
		
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		crlSource.setProxySource(onlineCRLSource);
		revocationToken = crlSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(revocationToken);
		assertNotNull(revocationToken.getRevocationTokenKey());
		
		RevocationToken savedRevocationToken = crlSource.findRevocation(revocationToken.getRevocationTokenKey(), certificateToken, rootToken);
		assertNotNull(savedRevocationToken);
		assertEquals(revocationToken.getRevocationTokenKey(), savedRevocationToken.getRevocationTokenKey());
		assertEquals(revocationToken.getNextUpdate(), savedRevocationToken.getNextUpdate());
	}
	
	@After
	public void cleanUp() throws SQLException {
		crlSource.destroyDao();
		dataSource.setUrl("jdbc:h2:mem:test;drop=true");
		// uncomment if webserver is active
		//webServer.stop();
		//webServer.shutdown();
	}

}
