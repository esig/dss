package eu.europa.esig.dss.client.revocation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.sql.SQLException;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.ocsp.JdbcCacheOCSPSource;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;

public class JdbcCacheOcspSourceTest {
	
	private JdbcDataSource dataSource = new JdbcDataSource();
	
	private JdbcCacheOCSPSource ocspSource = new JdbcCacheOCSPSource();
	
	@Before
	public void setUp() throws SQLException {		
		dataSource.setUrl("jdbc:h2:mem:test;create=true;DB_CLOSE_DELAY=-1");
		ocspSource.setDataSource(dataSource);
		ocspSource.initDao();
	}
	
	@Test
	public void test() throws SQLException {
		RevocationToken revocationToken = null;
		
		CertificateToken certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		CertificateToken rootToken = DSSUtils.loadCertificate(new File("src/test/resources/CALT.crt"));
		revocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNull(revocationToken);
		
		OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
		ocspSource.setProxySource(onlineOCSPSource);
		revocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(revocationToken);
		
		String key = ocspSource.initRevocationTokenKey(certificateToken, rootToken);
		assertNotNull(key);
		revocationToken = ocspSource.findRevocation(key, certificateToken, rootToken);
		assertNotNull(revocationToken);
	}
	
	@After
	public void cleanUp() throws SQLException {
		ocspSource.destroyDao();
		dataSource.setUrl("jdbc:h2:mem:test;drop=true");
	}
	
}
