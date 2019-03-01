package eu.europa.esig.dss.client.revocation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.sql.SQLException;

import org.apache.commons.codec.binary.Hex;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.ocsp.JdbcCacheOCSPSource;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.RevocationToken;

public class JdbcCacheOcspSourceTest {
	
	private JdbcDataSource dataSource = new JdbcDataSource();
	
	private JdbcCacheOCSPSource ocspSource = new JdbcCacheOCSPSource();
	
	@Before
	public void setUp() throws SQLException {		
		dataSource.setUrl("jdbc:h2:mem:test;create=true;DB_CLOSE_DELAY=-1");
		ocspSource.setDataSource(dataSource);
		ocspSource.initTable();
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
		ocspSource.setCacheExpirationTime(180000); // cache expiration in 180 seconds
		revocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(revocationToken);
		assertNotNull(revocationToken.getRevocationTokenKey());
		assertEquals(RevocationOrigin.EXTERNAL, revocationToken.getOrigin());

		RevocationToken savedRevocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(savedRevocationToken);
		assertEquals(revocationToken.getRevocationTokenKey(), savedRevocationToken.getRevocationTokenKey());
		assertEquals(revocationToken.getAbbreviation(), savedRevocationToken.getAbbreviation());
		assertEquals(revocationToken.getCreationDate(), savedRevocationToken.getCreationDate());
		assertEquals(revocationToken.getDSSIdAsString(), savedRevocationToken.getDSSIdAsString());
		assertEquals(Hex.encodeHexString(revocationToken.getEncoded()), Hex.encodeHexString(savedRevocationToken.getEncoded()));
		assertEquals(Hex.encodeHexString(revocationToken.getIssuerX500Principal().getEncoded()), Hex.encodeHexString(savedRevocationToken.getIssuerX500Principal().getEncoded()));
		assertEquals(revocationToken.getNextUpdate(), savedRevocationToken.getNextUpdate());
		assertEquals(RevocationOrigin.CACHED, savedRevocationToken.getOrigin());
		assertNotEquals(revocationToken.getOrigin(), savedRevocationToken.getOrigin());
		assertEquals(revocationToken.getProductionDate(), savedRevocationToken.getProductionDate());
		assertEquals(Hex.encodeHexString(revocationToken.getPublicKeyOfTheSigner().getEncoded()), Hex.encodeHexString(savedRevocationToken.getPublicKeyOfTheSigner().getEncoded()));
		assertEquals(revocationToken.getReason(), savedRevocationToken.getReason());
		assertEquals(revocationToken.getRelatedCertificateID(), savedRevocationToken.getRelatedCertificateID());
		assertEquals(revocationToken.getRevocationDate(), savedRevocationToken.getRevocationDate());
		assertEquals(revocationToken.getSignatureAlgorithm().getEncryptionAlgorithm().name(), savedRevocationToken.getSignatureAlgorithm().getEncryptionAlgorithm().name());
		assertEquals(revocationToken.getSourceURL(), savedRevocationToken.getSourceURL());
		assertEquals(revocationToken.getStatus(), savedRevocationToken.getStatus());
		assertEquals(revocationToken.getThisUpdate(), savedRevocationToken.getThisUpdate());
		
	}
	
	@After
	public void cleanUp() throws SQLException {
		ocspSource.destroyTable();
		dataSource.setUrl("jdbc:h2:mem:test;drop=true");
	}
	
}
