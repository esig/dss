package eu.europa.esig.dss.service.ocsp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.sql.SQLException;
import java.util.Date;

import org.apache.commons.codec.binary.Hex;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;

public class JdbcCacheOcspSourceTest {

	private static final Logger LOG = LoggerFactory.getLogger(JdbcCacheOcspSourceTest.class);
	
	private JdbcCacheOCSPSource ocspSource = new MockJdbcCacheOCSPSource();
	
	private JdbcDataSource dataSource = new JdbcDataSource();
	
	private OCSPToken storedRevocationToken = null;
	private Date requestTime = null;
	
	@Before
	public void setUp() throws SQLException {
		dataSource.setUrl("jdbc:h2:mem:test;create=true;DB_CLOSE_DELAY=-1");
		ocspSource.setDataSource(dataSource);
		assertFalse(ocspSource.isTableExists());
		ocspSource.initTable();
		assertTrue(ocspSource.isTableExists());
	}
	
	@Test
	public void test() throws Exception {
		RevocationToken revocationToken = null;
		
		CertificateToken certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		CertificateToken rootToken = DSSUtils.loadCertificate(new File("src/test/resources/CALT.crt"));
		revocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNull(revocationToken);
		
		OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
		ocspSource.setProxySource(onlineOCSPSource);
		ocspSource.setDefaultNextUpdateDelay(180L); // cache expiration in 180 seconds
		revocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(revocationToken);
		assertNotNull(revocationToken.getRevocationTokenKey());
		assertEquals(RevocationOrigin.EXTERNAL, revocationToken.getFirstOrigin());
		requestTime = new Date();

		// check real {@code findRevocation()} method behavior
		RevocationToken savedRevocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(savedRevocationToken);
		assertEquals(revocationToken.getRevocationTokenKey(), savedRevocationToken.getRevocationTokenKey());
		assertEquals(revocationToken.getAbbreviation(), savedRevocationToken.getAbbreviation());
		assertEquals(revocationToken.getCreationDate(), savedRevocationToken.getCreationDate());
		assertEquals(revocationToken.getDSSIdAsString(), savedRevocationToken.getDSSIdAsString());
		assertEquals(Hex.encodeHexString(revocationToken.getEncoded()), Hex.encodeHexString(savedRevocationToken.getEncoded()));
		assertEquals(Hex.encodeHexString(revocationToken.getIssuerX500Principal().getEncoded()), Hex.encodeHexString(savedRevocationToken.getIssuerX500Principal().getEncoded()));
		assertEquals(revocationToken.getNextUpdate(), savedRevocationToken.getNextUpdate());
		assertEquals(RevocationOrigin.CACHED, savedRevocationToken.getFirstOrigin());
		assertNotEquals(revocationToken.getFirstOrigin(), savedRevocationToken.getFirstOrigin());
		assertEquals(revocationToken.getProductionDate(), savedRevocationToken.getProductionDate());
		assertEquals(Hex.encodeHexString(revocationToken.getPublicKeyOfTheSigner().getEncoded()), Hex.encodeHexString(savedRevocationToken.getPublicKeyOfTheSigner().getEncoded()));
		assertEquals(revocationToken.getReason(), savedRevocationToken.getReason());
		assertEquals(revocationToken.getRelatedCertificateID(), savedRevocationToken.getRelatedCertificateID());
		assertEquals(revocationToken.getRevocationDate(), savedRevocationToken.getRevocationDate());
		assertEquals(revocationToken.getSignatureAlgorithm().getEncryptionAlgorithm().name(), savedRevocationToken.getSignatureAlgorithm().getEncryptionAlgorithm().name());
		assertEquals(revocationToken.getSourceURL(), savedRevocationToken.getSourceURL());
		assertEquals(revocationToken.getStatus(), savedRevocationToken.getStatus());
		assertEquals(revocationToken.getThisUpdate(), savedRevocationToken.getThisUpdate());
		
		// check that token can be obtained more than once
		storedRevocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(storedRevocationToken);
		assertEquals(RevocationOrigin.CACHED, storedRevocationToken.getFirstOrigin());

		// check a dummy token with the old maxUpdateDelay
		RevocationToken refreshedRevocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(refreshedRevocationToken);
		assertEquals(RevocationOrigin.CACHED, refreshedRevocationToken.getFirstOrigin());
		
		// Force refresh (1 second)
		ocspSource.setMaxNextUpdateDelay(1L);
		Thread.sleep(1000);

		// check the dummy token with forcing one second refresh
		refreshedRevocationToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(refreshedRevocationToken);
		assertEquals(RevocationOrigin.EXTERNAL, refreshedRevocationToken.getFirstOrigin());

	}
	
	/**
	 * Mocked to avoid time synchronization issue between this computer time and the OCSP responder
	 * (remote server is synchronized with UTC)
	 */
	@SuppressWarnings("serial")
	private class MockJdbcCacheOCSPSource extends JdbcCacheOCSPSource {
		
		@Override
		protected OCSPToken findRevocation(String key, CertificateToken certificateToken,
				CertificateToken issuerCertificateToken) {
			if (storedRevocationToken == null) {
				return super.findRevocation(key, certificateToken, issuerCertificateToken);
			} else {
				LOG.info("ThisUpdate was overriden from {} to {}", storedRevocationToken.getThisUpdate(), requestTime);
				storedRevocationToken.getThisUpdate().setTime(requestTime.getTime());
				return storedRevocationToken;
			}
		}
	}
	
	@After
	public void cleanUp() throws SQLException {
		ocspSource.destroyTable();
		assertFalse(ocspSource.isTableExists());
	}
	
}
