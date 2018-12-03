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
package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.util.List;
import java.util.Set;

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
import eu.europa.esig.dss.x509.CertificateSourceType;
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
			assertEquals(TimestampType.ARCHIVE_TIMESTAMP, token.getTimeStampType());
			assertEquals(DigestAlgorithm.SHA256, token.getSignedDataDigestAlgo());
			assertTrue(Utils.isStringNotBlank(token.getEncodedSignedDataDigestValue()));
			assertNull(token.getSignatureAlgorithm());

			List<CertificateToken> tstCerts = token.getCertificates();
			for (CertificateToken certificateToken : tstCerts) {
				if (token.isSignedBy(certificateToken)) {
					break;
				}
			}

			assertNotNull(token.getPublicKeyOfTheSigner());

			assertNotNull(token.getSignatureAlgorithm());
			assertEquals(SignatureAlgorithm.RSA_SHA256, token.getSignatureAlgorithm());
			assertFalse(token.isSelfSigned());

			assertFalse(token.matchData(null));

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

	@Test
	public void eeTSTwithCerts() throws Exception {
		// request has been done with certReq = true
		// the token includes the certificate chain
		String base64TST = "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";
		TimestampToken timestampToken = new TimestampToken(Utils.fromBase64(base64TST), TimestampType.SIGNATURE_TIMESTAMP, new CertificatePool());
		assertNotNull(timestampToken);
		List<CertificateToken> certificates = timestampToken.getCertificates();
		assertTrue(Utils.isCollectionNotEmpty(certificates));
		for (CertificateToken certificateToken : certificates) {
			if (timestampToken.isSignedBy(certificateToken)) {
				break;
			}
		}
		assertTrue(timestampToken.isSignatureValid());
		assertTrue(timestampToken.matchData("Hello world".getBytes()));
	}

	@Test
	public void eeTSTwithoutCerts() throws Exception {
		// request has been done with certReq = false
		String base64TST = "MIAGCSqGSIb3DQEHAqCAMIIDvgIBAzEPMA0GCWCGSAFlAwQCAwUAMIGMBgsqhkiG9w0BCRABBKB9BHsweQIBAQYGBACPZwEBMFEwDQYJYIZIAWUDBAIDBQAEQLf3g7rtgpfw25F0YhhP9PCOacLV5fealCYA+XJfWM4fKcGBOb+AsGwP/yvdNHOEUuz0DEiMIqfj2Azfb5wcDUcCCBa/WWL5098BGA8yMDE4MDgwMTE0MzEzOVoxggMXMIIDEwIBATCBkTB9MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUCEE6s+2wj/FuOVAWWu7c7U0wwDQYJYIZIAWUDBAIDBQCgggFWMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMTgwODAxMTQzMTM5WjBPBgkqhkiG9w0BCQQxQgRAugviPUUMFKSe765lT1N6vY8xfngIhElj+q8qLwSn+T3sDHy7mGH9HgWg4ymttofnaO2AcbvLg+Crx+O+3ro5qjCByAYLKoZIhvcNAQkQAgwxgbgwgbUwgbIwga8EFAKxl+94ruFx9qFHX1DqzGVx8fwLMIGWMIGBpH8wfTELMAkGA1UEBhMCRUUxIjAgBgNVBAoMGUFTIFNlcnRpZml0c2VlcmltaXNrZXNrdXMxMDAuBgNVBAMMJ1RFU1Qgb2YgRUUgQ2VydGlmaWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlAhBOrPtsI/xbjlQFlru3O1NMMA0GCSqGSIb3DQEBAQUABIIBABNzVCdb7st5hDZAJTECbaFm1NAvt+r7fcJVjb+XJErb/yT3wBbouwrs1B6AhlMlr39ivzKltP6kT9yHpCWySzi66c++V1yGZEXsoH7tAZcEBTEsye+JVN5D71OoRhY9CAacZYxxoMcpa8/t/2aFFNoBOYbKlqUXklqAtEumjxvfK4yYzGcU7ESTNumMOMkg6bt1mAnaDvxtzamyjDzwUTKOr0R8s66y+zGXYXeJywX+hNIFpbme1RRbcxKs5src32J1JCLgL1gDuTMOwJKgCH+BtqRduK6KHAgwR0TWMhYyZPauesjJZ/o8dJgzUwmapl3Y++aF6UzpfC2uXboJuQkAAAAA";
		TimestampToken timestampToken = new TimestampToken(Utils.fromBase64(base64TST), TimestampType.SIGNATURE_TIMESTAMP, new CertificatePool());
		assertNotNull(timestampToken);
		assertFalse(Utils.isCollectionNotEmpty(timestampToken.getCertificates()));
		assertFalse(timestampToken.isSignatureValid());
		assertTrue(timestampToken.matchData("Hello world".getBytes()));
	}

	@Test
	public void eeTSTwithoutCertsAndCertPool() throws Exception {
		// request has been done with certReq = false
		String base64TST = "MIAGCSqGSIb3DQEHAqCAMIIDvgIBAzEPMA0GCWCGSAFlAwQCAwUAMIGMBgsqhkiG9w0BCRABBKB9BHsweQIBAQYGBACPZwEBMFEwDQYJYIZIAWUDBAIDBQAEQLf3g7rtgpfw25F0YhhP9PCOacLV5fealCYA+XJfWM4fKcGBOb+AsGwP/yvdNHOEUuz0DEiMIqfj2Azfb5wcDUcCCBa/WWL5098BGA8yMDE4MDgwMTE0MzEzOVoxggMXMIIDEwIBATCBkTB9MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUCEE6s+2wj/FuOVAWWu7c7U0wwDQYJYIZIAWUDBAIDBQCgggFWMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMTgwODAxMTQzMTM5WjBPBgkqhkiG9w0BCQQxQgRAugviPUUMFKSe765lT1N6vY8xfngIhElj+q8qLwSn+T3sDHy7mGH9HgWg4ymttofnaO2AcbvLg+Crx+O+3ro5qjCByAYLKoZIhvcNAQkQAgwxgbgwgbUwgbIwga8EFAKxl+94ruFx9qFHX1DqzGVx8fwLMIGWMIGBpH8wfTELMAkGA1UEBhMCRUUxIjAgBgNVBAoMGUFTIFNlcnRpZml0c2VlcmltaXNrZXNrdXMxMDAuBgNVBAMMJ1RFU1Qgb2YgRUUgQ2VydGlmaWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlAhBOrPtsI/xbjlQFlru3O1NMMA0GCSqGSIb3DQEBAQUABIIBABNzVCdb7st5hDZAJTECbaFm1NAvt+r7fcJVjb+XJErb/yT3wBbouwrs1B6AhlMlr39ivzKltP6kT9yHpCWySzi66c++V1yGZEXsoH7tAZcEBTEsye+JVN5D71OoRhY9CAacZYxxoMcpa8/t/2aFFNoBOYbKlqUXklqAtEumjxvfK4yYzGcU7ESTNumMOMkg6bt1mAnaDvxtzamyjDzwUTKOr0R8s66y+zGXYXeJywX+hNIFpbme1RRbcxKs5src32J1JCLgL1gDuTMOwJKgCH+BtqRduK6KHAgwR0TWMhYyZPauesjJZ/o8dJgzUwmapl3Y++aF6UzpfC2uXboJuQkAAAAA";
		TimestampToken timestampToken = new TimestampToken(Utils.fromBase64(base64TST), TimestampType.SIGNATURE_TIMESTAMP, new CertificatePool());
		assertNotNull(timestampToken);
		assertTrue(Utils.isCollectionEmpty(timestampToken.getCertificates()));
		assertFalse(timestampToken.isSignatureValid());
		assertTrue(timestampToken.matchData("Hello world".getBytes()));

		CertificatePool certPool = new CertificatePool();
		String base64TsuCert = "MIIEFTCCAv2gAwIBAgIQTqz7bCP8W45UBZa7tztTTDANBgkqhkiG9w0BAQsFADB9MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUwHhcNMTQwOTAyMTAwNjUxWhcNMjQwOTAyMTAwNjUxWjBdMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEMMAoGA1UECwwDVFNBMRwwGgYDVQQDDBNERU1PIG9mIFNLIFRTQSAyMDE0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAysgrVnVPxH8jNgCsJw0y+7fmmBDTM/tNB+xielnP9KcuQ+nyTgNu1JMpnry7Rh4ndr54rPLXNGVdb/vsgsi8B558DisPVUn3Rur3/8XQ+BCkhTQIg1cSmyCsWxJgeaQKJi6WGVaQWB2he35aVhL5F6ae/gzXT3sGGwnWujZkY9o5RapGV15+/b7Uv+7jWYFAxcD6ba5jI00RY/gmsWwKb226Rnz/pXKDBfuN3ox7y5/lZf5+MyIcVe1qJe7VAJGpJFjNq+BEEdvfqvJ1PiGQEDJAPhRqahVjBSzqZhJQoL3HI42NRCFwarvdnZYoCPxjeYpAynTHgNR7kKGX1iQ8OQIDAQABo4GwMIGtMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUJwScZQxzlzySVqZXviXpKZDV5NwwHwYDVR0jBBgwFoAUtTQKnaUvEMXnIQ6+xLFlRxsDdv4wQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly93d3cuc2suZWUvcmVwb3NpdG9yeS9jcmxzL3Rlc3RfZWVjY3JjYS5jcmwwDQYJKoZIhvcNAQELBQADggEBAIq02SVKwP1UolKjqAQe7SVY/Kgi++G2kqAd40UmMqa94GTu91LFZR5TvdoyZjjnQ2ioXh5CV2lflUy/lUrZMDpqEe7IbjZW5+b9n5aBvXYJgDua9SYjMOrcy3siytqq8UbNgh79ubYgWhHhJSnLWK5YJ+5vQjTpOMdRsLp/D+FhTUa6mP0UDY+U82/tFufkd9HW4zbalUWhQgnNYI3oo0CsZ0HExuynOOZmM1Bf8PzD6etlLSKkYB+mB77Omqgflzz+Jjyh45o+305MRzHDFeJZx7WxC+XTNWQ0ZFTFfc0ozxxzUWUlfNfpWyQh3+4LbeSQRWrNkbNRfCpYotyM6AY=";
		CertificateToken tsuCert = DSSUtils.loadCertificateFromBase64EncodedString(base64TsuCert);
		certPool.getInstance(tsuCert, CertificateSourceType.OTHER);

		SignatureValidationContext svc = new SignatureValidationContext(certPool);
		svc.initialize(new CommonCertificateVerifier());
		svc.addTimestampTokenForVerification(timestampToken);
		svc.validate();

		Set<TimestampToken> timestamps = svc.getProcessedTimestamps();
		assertEquals(1, timestamps.size());
		TimestampToken validationResult = timestamps.iterator().next();
		assertTrue(validationResult.isSignatureValid());
	}


}
