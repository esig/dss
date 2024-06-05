package eu.europa.esig.dss.spi.validation;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TimestampTokenVerifierTest {

    @Test
    public void test() throws Exception {
        String base64TST = "MIAGCSqGSIb3DQEHAqCAMIIDvgIBAzEPMA0GCWCGSAFlAwQCAwUAMIGMBgsqhkiG9w0BCRABBKB9BHsweQIBAQYGBACPZwEBMFEwDQYJYIZIAWUDBAIDBQAEQLf3g7rtgpfw25F0YhhP9PCOacLV5fealCYA+XJfWM4fKcGBOb+AsGwP/yvdNHOEUuz0DEiMIqfj2Azfb5wcDUcCCBa/WWL5098BGA8yMDE4MDgwMTE0MzEzOVoxggMXMIIDEwIBATCBkTB9MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUCEE6s+2wj/FuOVAWWu7c7U0wwDQYJYIZIAWUDBAIDBQCgggFWMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMTgwODAxMTQzMTM5WjBPBgkqhkiG9w0BCQQxQgRAugviPUUMFKSe765lT1N6vY8xfngIhElj+q8qLwSn+T3sDHy7mGH9HgWg4ymttofnaO2AcbvLg+Crx+O+3ro5qjCByAYLKoZIhvcNAQkQAgwxgbgwgbUwgbIwga8EFAKxl+94ruFx9qFHX1DqzGVx8fwLMIGWMIGBpH8wfTELMAkGA1UEBhMCRUUxIjAgBgNVBAoMGUFTIFNlcnRpZml0c2VlcmltaXNrZXNrdXMxMDAuBgNVBAMMJ1RFU1Qgb2YgRUUgQ2VydGlmaWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlAhBOrPtsI/xbjlQFlru3O1NMMA0GCSqGSIb3DQEBAQUABIIBABNzVCdb7st5hDZAJTECbaFm1NAvt+r7fcJVjb+XJErb/yT3wBbouwrs1B6AhlMlr39ivzKltP6kT9yHpCWySzi66c++V1yGZEXsoH7tAZcEBTEsye+JVN5D71OoRhY9CAacZYxxoMcpa8/t/2aFFNoBOYbKlqUXklqAtEumjxvfK4yYzGcU7ESTNumMOMkg6bt1mAnaDvxtzamyjDzwUTKOr0R8s66y+zGXYXeJywX+hNIFpbme1RRbcxKs5src32J1JCLgL1gDuTMOwJKgCH+BtqRduK6KHAgwR0TWMhYyZPauesjJZ/o8dJgzUwmapl3Y++aF6UzpfC2uXboJuQkAAAAA";
        TimestampToken timestampToken = new TimestampToken(Utils.fromBase64(base64TST), TimestampType.SIGNATURE_TIMESTAMP);
        assertTrue(timestampToken.matchData(new InMemoryDocument("Hello world".getBytes())));

        TimestampTokenVerifier timestampTokenVerifier = TimestampTokenVerifier.createDefaultTimestampTokenVerifier();
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));

        timestampTokenVerifier.setAcceptUntrustedCertificateChains(true);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));

        String base64TsuCert = "MIIEFTCCAv2gAwIBAgIQTqz7bCP8W45UBZa7tztTTDANBgkqhkiG9w0BAQsFADB9MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUwHhcNMTQwOTAyMTAwNjUxWhcNMjQwOTAyMTAwNjUxWjBdMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEMMAoGA1UECwwDVFNBMRwwGgYDVQQDDBNERU1PIG9mIFNLIFRTQSAyMDE0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAysgrVnVPxH8jNgCsJw0y+7fmmBDTM/tNB+xielnP9KcuQ+nyTgNu1JMpnry7Rh4ndr54rPLXNGVdb/vsgsi8B558DisPVUn3Rur3/8XQ+BCkhTQIg1cSmyCsWxJgeaQKJi6WGVaQWB2he35aVhL5F6ae/gzXT3sGGwnWujZkY9o5RapGV15+/b7Uv+7jWYFAxcD6ba5jI00RY/gmsWwKb226Rnz/pXKDBfuN3ox7y5/lZf5+MyIcVe1qJe7VAJGpJFjNq+BEEdvfqvJ1PiGQEDJAPhRqahVjBSzqZhJQoL3HI42NRCFwarvdnZYoCPxjeYpAynTHgNR7kKGX1iQ8OQIDAQABo4GwMIGtMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUJwScZQxzlzySVqZXviXpKZDV5NwwHwYDVR0jBBgwFoAUtTQKnaUvEMXnIQ6+xLFlRxsDdv4wQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly93d3cuc2suZWUvcmVwb3NpdG9yeS9jcmxzL3Rlc3RfZWVjY3JjYS5jcmwwDQYJKoZIhvcNAQELBQADggEBAIq02SVKwP1UolKjqAQe7SVY/Kgi++G2kqAd40UmMqa94GTu91LFZR5TvdoyZjjnQ2ioXh5CV2lflUy/lUrZMDpqEe7IbjZW5+b9n5aBvXYJgDua9SYjMOrcy3siytqq8UbNgh79ubYgWhHhJSnLWK5YJ+5vQjTpOMdRsLp/D+FhTUa6mP0UDY+U82/tFufkd9HW4zbalUWhQgnNYI3oo0CsZ0HExuynOOZmM1Bf8PzD6etlLSKkYB+mB77Omqgflzz+Jjyh45o+305MRzHDFeJZx7WxC+XTNWQ0ZFTFfc0ozxxzUWUlfNfpWyQh3+4LbeSQRWrNkbNRfCpYotyM6AY=";
        CertificateToken tsuCert = DSSUtils.loadCertificateFromBase64EncodedString(base64TsuCert);

        assertTrue(timestampToken.isSignedBy(tsuCert));

        timestampTokenVerifier.setAcceptUntrustedCertificateChains(false);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        timestampTokenVerifier.setAcceptUntrustedCertificateChains(true);
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken));
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(tsuCert);
        timestampTokenVerifier.setTrustedCertificateSource(trustedCertificateSource);

        timestampTokenVerifier.setAcceptUntrustedCertificateChains(false);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        timestampTokenVerifier.setAcceptUntrustedCertificateChains(true);
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken));
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        assertFalse(timestampToken.matchData(new InMemoryDocument("Bye world".getBytes())));

        timestampTokenVerifier.setAcceptUntrustedCertificateChains(false);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        timestampTokenVerifier.setAcceptUntrustedCertificateChains(true);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));
    }

}
