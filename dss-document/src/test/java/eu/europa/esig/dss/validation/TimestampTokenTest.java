package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;

import org.bouncycastle.cms.CMSException;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.TimestampType;

public class TimestampTokenTest {

	@Test(expected = CMSException.class)
	public void incorrectTimestamp() throws Exception {
		new TimestampToken(new byte[] { 1, 2, 3 }, TimestampType.ARCHIVE_TIMESTAMP, new CertificatePool());
	}

	@Test
	public void correctToken() throws Exception {
		try (FileInputStream fis = new FileInputStream("src/test/resources/archive_timestamp.tst")) {
			TimestampToken token = new TimestampToken(Utils.toByteArray(fis), TimestampType.ARCHIVE_TIMESTAMP, new CertificatePool());
			assertNotNull(token);
			assertNotNull(token.getGenerationTime());
			assertTrue(Utils.isCollectionNotEmpty(token.getCertificates()));
			assertNotNull(token.getSignatureAlgorithm());
			assertEquals(TimestampType.ARCHIVE_TIMESTAMP, token.getTimeStampType());
			assertEquals(DigestAlgorithm.SHA256, token.getSignedDataDigestAlgo());
			assertEquals(SignatureAlgorithm.RSA_SHA256, token.getSignatureAlgorithm());
			assertTrue(Utils.isStringNotBlank(token.getEncodedSignedDataDigestValue()));

			assertNotNull(token.getIssuerToken());
			assertTrue(token.isSignedBy(token.getIssuerToken()));
			assertFalse(token.isSelfSigned());

			assertFalse(token.matchData(new byte[] { 1, 2, 3 }));
			assertTrue(token.isMessageImprintDataFound());
			assertFalse(token.isMessageImprintDataIntact());

			assertTrue(token.matchData(DSSUtils.toByteArray(new FileDocument("src/test/resources/timestamped.xml"))));
			assertTrue(token.isMessageImprintDataFound());
			assertTrue(token.isMessageImprintDataIntact());

		}
	}

}
