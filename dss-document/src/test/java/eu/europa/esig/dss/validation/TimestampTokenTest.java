package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;

import org.bouncycastle.cms.CMSException;
import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.TimestampType;

public class TimestampTokenTest {

	@Test(expected = CMSException.class)
	public void incorrectTimestamp() throws Exception {
		new TimestampToken(new byte[] { 1, 2, 3 }, TimestampType.ARCHIVE_TIMESTAMP, new CertificatePool());
	}

	@Test
	public void createToken() throws Exception {
		try (FileInputStream fis = new FileInputStream("src/test/resources/archive_timestamp.tst")) {
			TimestampToken token = new TimestampToken(Utils.toByteArray(fis), TimestampType.ARCHIVE_TIMESTAMP, new CertificatePool());
			assertNotNull(token);
			assertNotNull(token.getGenerationTime());
			assertTrue(Utils.isCollectionNotEmpty(token.getCertificates()));

			assertNotNull(token.getSignatureAlgorithm());
		}
	}

}
