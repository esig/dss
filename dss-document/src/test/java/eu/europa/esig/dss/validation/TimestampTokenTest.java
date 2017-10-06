package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.TimestampType;

public class TimestampTokenTest {

	private static final Logger LOG = LoggerFactory.getLogger(TimestampTokenTest.class);

	private static final String TIMETAMPED_DATA_B64 = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPGFzaWM6QVNpQ0FyY2hpdmVNYW5pZmVzdCB4bWxuczphc2ljPSJodHRwOi8vdXJpLmV0c2kub3JnLzAyOTE4L3YxLjIuMSMiPgoJPGFzaWM6U2lnUmVmZXJlbmNlIFVSST0iTUVUQS1JTkYvYXJjaGl2ZV90aW1lc3RhbXAudHN0IiBNaW1lVHlwZT0iYXBwbGljYXRpb24vdm5kLmV0c2kudGltZXN0YW1wLXRva2VuIi8+Cgk8YXNpYzpEYXRhT2JqZWN0UmVmZXJlbmNlIFVSST0iTUVUQS1JTkYvc2lnbmF0dXJlLnA3cyIgTWltZVR5cGU9ImFwcGxpY2F0aW9uL3gtcGtjczctc2lnbmF0dXJlIj4KCQk8ZHM6RGlnZXN0TWV0aG9kIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPgoJCTxkczpEaWdlc3RWYWx1ZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+M1Flb3M4V01ZWHU1L3E2RzFIdjVnMDVnamtYS2VjSzBVQUxNU2UrZWVJbz08L2RzOkRpZ2VzdFZhbHVlPgoJPC9hc2ljOkRhdGFPYmplY3RSZWZlcmVuY2U+Cgk8YXNpYzpEYXRhT2JqZWN0UmVmZXJlbmNlIFVSST0idG9CZVNpZ25lZC50eHQiIE1pbWVUeXBlPSJ0ZXh0L3BsYWluIj4KCQk8ZHM6RGlnZXN0TWV0aG9kIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPgoJCTxkczpEaWdlc3RWYWx1ZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+SkpadDQxTnQ4VnNZYWhQK1h0aTRyUjN2QkRrVWZSZDZncXVJdGw2UjVPcz08L2RzOkRpZ2VzdFZhbHVlPgoJPC9hc2ljOkRhdGFPYmplY3RSZWZlcmVuY2U+Cgk8YXNpYzpEYXRhT2JqZWN0UmVmZXJlbmNlIFVSST0idG9CZVNpZ25lZC5wZGYiIE1pbWVUeXBlPSJhcHBsaWNhdGlvbi9wZGYiPgoJCTxkczpEaWdlc3RNZXRob2QgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+CgkJPGRzOkRpZ2VzdFZhbHVlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj5JT0lxQ0phWjJXUDF2V0t6VFZsc3Rzeno0RTVod0xhVVBEUnRVVE9YZU5jPTwvZHM6RGlnZXN0VmFsdWU+Cgk8L2FzaWM6RGF0YU9iamVjdFJlZmVyZW5jZT4KCTxhc2ljOkRhdGFPYmplY3RSZWZlcmVuY2UgVVJJPSJNRVRBLUlORi9BU2lDTWFuaWZlc3RfMS54bWwiIE1pbWVUeXBlPSJ0ZXh0L3htbCI+CgkJPGRzOkRpZ2VzdE1ldGhvZCB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4KCQk8ZHM6RGlnZXN0VmFsdWUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPmc1ZFloNjFFdkhWdGNCUHMyRG1YZmhYN1lubGxaZzAxMnBid3lkVFR5N2c9PC9kczpEaWdlc3RWYWx1ZT4KCTwvYXNpYzpEYXRhT2JqZWN0UmVmZXJlbmNlPgo8L2FzaWM6QVNpQ0FyY2hpdmVNYW5pZmVzdD4K";

	@Test(expected = CMSException.class)
	public void incorrectTimestamp() throws Exception {
		new TimestampToken(new byte[] { 1, 2, 3 }, TimestampType.ARCHIVE_TIMESTAMP, new CertificatePool());
	}

	@Test
	public void correctToken() throws Exception {
		CertificateToken wrongToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));

		try (FileInputStream fis = new FileInputStream("src/test/resources/archive_timestamp.tst")) {
			byte[] byteArray = Utils.toByteArray(fis);
			TimestampToken token = new TimestampToken(byteArray, TimestampType.ARCHIVE_TIMESTAMP, new CertificatePool());
			assertNotNull(token);
			LOG.info(token.toString());

			assertFalse(token.isSignedBy(wrongToken));
			assertNotNull(token.getGenerationTime());
			assertNotNull(token.getAbbreviation());
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

			assertTrue(token.matchData(Utils.fromBase64(TIMETAMPED_DATA_B64)));
			assertTrue(token.isMessageImprintDataFound());
			assertTrue(token.isMessageImprintDataIntact());

			byte[] encoded = token.getEncoded();
			TimeStampToken tst = new TimeStampToken(new CMSSignedData(encoded));
			assertNotNull(tst);
		}
	}

}
