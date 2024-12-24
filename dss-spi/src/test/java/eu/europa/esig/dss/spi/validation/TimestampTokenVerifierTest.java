/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.validation;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TimestampTokenVerifierTest {

    @Test
    void revocationCheckIgnoreTest() throws Exception {
        String base64TST = "MIAGCSqGSIb3DQEHAqCAMIIDvgIBAzEPMA0GCWCGSAFlAwQCAwUAMIGMBgsqhkiG9w0BCRABBKB9BHsweQIBAQYGBACPZwEBMFEwDQYJYIZIAWUDBAIDBQAEQLf3g7rtgpfw25F0YhhP9PCOacLV5fealCYA+XJfWM4fKcGBOb+AsGwP/yvdNHOEUuz0DEiMIqfj2Azfb5wcDUcCCBa/WWL5098BGA8yMDE4MDgwMTE0MzEzOVoxggMXMIIDEwIBATCBkTB9MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUCEE6s+2wj/FuOVAWWu7c7U0wwDQYJYIZIAWUDBAIDBQCgggFWMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMTgwODAxMTQzMTM5WjBPBgkqhkiG9w0BCQQxQgRAugviPUUMFKSe765lT1N6vY8xfngIhElj+q8qLwSn+T3sDHy7mGH9HgWg4ymttofnaO2AcbvLg+Crx+O+3ro5qjCByAYLKoZIhvcNAQkQAgwxgbgwgbUwgbIwga8EFAKxl+94ruFx9qFHX1DqzGVx8fwLMIGWMIGBpH8wfTELMAkGA1UEBhMCRUUxIjAgBgNVBAoMGUFTIFNlcnRpZml0c2VlcmltaXNrZXNrdXMxMDAuBgNVBAMMJ1RFU1Qgb2YgRUUgQ2VydGlmaWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlAhBOrPtsI/xbjlQFlru3O1NMMA0GCSqGSIb3DQEBAQUABIIBABNzVCdb7st5hDZAJTECbaFm1NAvt+r7fcJVjb+XJErb/yT3wBbouwrs1B6AhlMlr39ivzKltP6kT9yHpCWySzi66c++V1yGZEXsoH7tAZcEBTEsye+JVN5D71OoRhY9CAacZYxxoMcpa8/t/2aFFNoBOYbKlqUXklqAtEumjxvfK4yYzGcU7ESTNumMOMkg6bt1mAnaDvxtzamyjDzwUTKOr0R8s66y+zGXYXeJywX+hNIFpbme1RRbcxKs5src32J1JCLgL1gDuTMOwJKgCH+BtqRduK6KHAgwR0TWMhYyZPauesjJZ/o8dJgzUwmapl3Y++aF6UzpfC2uXboJuQkAAAAA";
        TimestampToken timestampToken = new TimestampToken(Utils.fromBase64(base64TST), TimestampType.SIGNATURE_TIMESTAMP);
        assertTrue(timestampToken.matchData(new InMemoryDocument("Hello world".getBytes())));

        TimestampTokenVerifier timestampTokenVerifier = TimestampTokenVerifier.createDefaultTimestampTokenVerifier();
        RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        revocationDataVerifier.setAcceptTimestampCertificatesWithoutRevocation(true);
        timestampTokenVerifier.setRevocationDataVerifier(revocationDataVerifier);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));

        TrustAnchorVerifier trustAnchorVerifier = TrustAnchorVerifier.createDefaultTrustAnchorVerifier();
        timestampTokenVerifier.setTrustAnchorVerifier(trustAnchorVerifier);

        trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(true);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));

        String base64TsuCert = "MIIEFTCCAv2gAwIBAgIQTqz7bCP8W45UBZa7tztTTDANBgkqhkiG9w0BAQsFADB9MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUwHhcNMTQwOTAyMTAwNjUxWhcNMjQwOTAyMTAwNjUxWjBdMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEMMAoGA1UECwwDVFNBMRwwGgYDVQQDDBNERU1PIG9mIFNLIFRTQSAyMDE0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAysgrVnVPxH8jNgCsJw0y+7fmmBDTM/tNB+xielnP9KcuQ+nyTgNu1JMpnry7Rh4ndr54rPLXNGVdb/vsgsi8B558DisPVUn3Rur3/8XQ+BCkhTQIg1cSmyCsWxJgeaQKJi6WGVaQWB2he35aVhL5F6ae/gzXT3sGGwnWujZkY9o5RapGV15+/b7Uv+7jWYFAxcD6ba5jI00RY/gmsWwKb226Rnz/pXKDBfuN3ox7y5/lZf5+MyIcVe1qJe7VAJGpJFjNq+BEEdvfqvJ1PiGQEDJAPhRqahVjBSzqZhJQoL3HI42NRCFwarvdnZYoCPxjeYpAynTHgNR7kKGX1iQ8OQIDAQABo4GwMIGtMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUJwScZQxzlzySVqZXviXpKZDV5NwwHwYDVR0jBBgwFoAUtTQKnaUvEMXnIQ6+xLFlRxsDdv4wQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly93d3cuc2suZWUvcmVwb3NpdG9yeS9jcmxzL3Rlc3RfZWVjY3JjYS5jcmwwDQYJKoZIhvcNAQELBQADggEBAIq02SVKwP1UolKjqAQe7SVY/Kgi++G2kqAd40UmMqa94GTu91LFZR5TvdoyZjjnQ2ioXh5CV2lflUy/lUrZMDpqEe7IbjZW5+b9n5aBvXYJgDua9SYjMOrcy3siytqq8UbNgh79ubYgWhHhJSnLWK5YJ+5vQjTpOMdRsLp/D+FhTUa6mP0UDY+U82/tFufkd9HW4zbalUWhQgnNYI3oo0CsZ0HExuynOOZmM1Bf8PzD6etlLSKkYB+mB77Omqgflzz+Jjyh45o+305MRzHDFeJZx7WxC+XTNWQ0ZFTFfc0ozxxzUWUlfNfpWyQh3+4LbeSQRWrNkbNRfCpYotyM6AY=";
        CertificateToken tsuCert = DSSUtils.loadCertificateFromBase64EncodedString(base64TsuCert);

        assertTrue(timestampToken.isSignedBy(tsuCert));

        trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(false);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(true);
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken));
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(false);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        timestampTokenVerifier.setTrustAnchorVerifier(trustAnchorVerifier);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustAnchorVerifier.setTrustedCertificateSource(trustedCertificateSource);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        trustedCertificateSource.addCertificate(tsuCert);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
        Map<CertificateToken, List<CertificateTrustTime>> trustTimeByCertMap = new HashMap<>();

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 2);
        Date endDate = calendar.getTime();

        trustTimeByCertMap.put(tsuCert, Collections.singletonList(new CertificateTrustTime(startDate, endDate)));
        trustedListsCertificateSource.setTrustTimeByCertificates(trustTimeByCertMap);
        trustAnchorVerifier.setTrustedCertificateSource(trustedListsCertificateSource);

        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, new Date()));
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert), new Date()));

        calendar.add(Calendar.YEAR, 1);
        Date futureDate = calendar.getTime();
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert), futureDate));

        trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(true);
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken));
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        assertFalse(timestampToken.matchData(new InMemoryDocument("Bye world".getBytes())));

        trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(false);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));

        trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(true);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, Collections.singletonList(tsuCert)));
    }

    @Test
    void revocationCheckTest() throws Exception {
        String base64TST = "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";
        TimestampToken timestampToken = new TimestampToken(Utils.fromBase64(base64TST), TimestampType.SIGNATURE_TIMESTAMP);
        assertTrue(timestampToken.matchData(new InMemoryDocument("Hello world".getBytes())));

        String tstCertBase64 = "MIIE8zCCA1ugAwIBAgICAfQwDQYJKoZIhvcNAQENBQAwTTEQMA4GA1UEAwwHcm9vdC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTIzMDUxMTA5MzAxMloXDTI1MDMxMTA5MzAxMlowTjERMA8GA1UEAwwIZ29vZC10c2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAI90c+5Vqoe1InmTeTT7NrK+7x+mDMsQ1BUjF0gFH/8i+uCKO1+H+btNG1MGqyyiPKNHMQNZNCXtZSPID06mlGXDiydP/E2iE96HdzEbBgNwwQBwOYjVH7Y2D7b/F0lEYZb41a2EyXAY5wHhRBI7AA/DNonmIt90NuVMgMEwGfpFKCLuyhkiOj0ukhaqyJoCEgNI75+6amHCAgerpnVmYfAE3XouJ6xA3egm2t469pvx5IjjaaT+VgLlmcHC/ynmvX+2XtOYFNOuCioapa9WoV3D0QYTLRbhpTPg4vgIaaPgLPsHZo+jx8Z5LYi4yeXmCouhj0wSb7wc6HcQNurBl/cKBey7olqfj+nAHWYl4mMePnE1zUHLUaFHoxFsOj1hj97LYeE5u2HI1ZoHAOyrfD4eMgizpg6mHnhB++lr4SZXZe9WPAwT6C48rKXa55qynmOMBDNmx4UwE80fx+jNbnZEU2edF4fBcyjzusAvK6WcU6evWnboe4h9VCRaU3ldcwIDAQABo4HbMIHYMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcmwvcm9vdC1jYS5jcmwwTAYIKwYBBQUHAQEEQDA+MDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvcm9vdC1jYS5jcnQwHQYDVR0OBBYEFJywlyojxLwGuQ4SvBZbAqt76HO4MA0GCSqGSIb3DQEBDQUAA4IBgQA2Hh9nCuKoIiaNp8cOiehNoPhhA1U6z+28q23Yi8oPMqyGyf8NQgNaohN6v2DrYpRxErZJLPflmHNsgGcrl44SRatar78HCcxnbsB8aBEzFkkMlxcK1YcUakPYYLsA9xRxhrYMaXjbJM/FR4XJaAj1uLaf6z6OhDzdP9xvqgBCOYGeyXlp6/D2LEYTQUALp8skKrKmenGheH9/6JjVjHl4+FPHKTfymdoxAymgSqvFycnpnLUSM9M3myFp9BB0qHMMJIwM1o2D7wUV/r2fR01LTaVj3WDXbR1UHrDqEXaKEb7P7J3737IRuTw8qeAZsMrxCgYYbygg/N6mjRAg0jB2/mnqXszUI0BA1dboyuwzuadPEJcweG4b0rC5njOhH5Eq9Tfj2ixOS7H6lk8jIoHWQnQRaZijQJRMx3LKLqKKEFRtF6C7lafRGUnrWSU2/c6rcKI5Jv2Mo1OSdg5dQMotUx8NGYIFHsTVuZzMPM5l7SqZ2tpUQaWaolzzSZf3ZNo=";
        CertificateToken tstCert = DSSUtils.loadCertificateFromBase64EncodedString(tstCertBase64);
        assertTrue(timestampToken.isSignedBy(tstCert));

        String trustedCertBase64 = "MIIEVzCCAr+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjMwNDExMDkzMDEyWhcNMjUwNDExMDkzMDEyWjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQChAl5g1wWKs3If1lebUeFVWxNO60uYMtUV60Sat2shEsRmnmHD1cWTyK1blEQpxKFbjxqNIoVabmBzMT3pdS8oaAuQXCx5zaVGU83NXuAELg1V3GbjmbEj1sMeE1cVEceb1GJJgCw2s0P6++opalJHC+8loihRUi2hZE6NoEHYPcjqBSXWfOzsiuCA0aEoanRwZ7UG/uqdZYShAh59Juan56fhy78cvBQn0N0njij8dk+0e7JFf+LBRORLTAGSlyepVx6MST8ZoQ51HusZnfdG/LO1DWoqsdS26y+PasiNee5xNa1FOEViWh5V9AH8kFmE3DO0TOG640ure5nA7BkQ/1+eF1BqRuaZq8HERZbm7OVViO06gTJRpxtGuZigUtUTPc03On38c0xTMO4GhvsgnTHs2T7ABJY0hKkoygtVBwhH2JUexdjfqqOL5YYaR0kHXmSXq/O2aqwPRbeD8DzOIsB2UiYeX4374iXGTj7CqRHH0+gK5g5z5z/P80Abu1sCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRTxpLeSvXLPe4DdyS/cuVe/jbJjTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBgQBuMzdr4TUo6Kezeds1fmespxtWxkUTWQzSlFCnG3cpg5TLb/2aOx/2/9oiL4/CRW/sIS5jRAqd4+6cN+o7YuYYEPVMnLM2LLyyZjR7xH64PMzmlIOvxqIbXom8i2SY+7GHGnB00pDkJCDHVfZwLshCGOql4QgPbW1hz5Q81B95BJbC3AVyH6wWl5JUJ+SX16UEm9WE2Eoyqv4JNov3ZrU9tYjU3sqwu4CzE92RiBIYuaZ875pifemU97EZnWEZxOeF1jgHN5llWMeLt6ZwW/lWWFHaTjzy0HiijmAa984G5Iir3yMgyTqeDniZYGn3YjrM6vQTL0/B682BX6pADV4vLIrwcyWHUVqHUOXdvVipOkKFTrATgY2oW5VSsEJrGafDqb6MXfSjiv7ouTlY8eEslcV14Tt7KeDrSjOjzFfr5xSF+Amay9lUaDFWRGeAvMeJ1tqe1dwp+7G8Uh40bvO2KdduklD5LT671/pRbOWr5XItyu4rMfLhIM4DuHGnqck=";
        CertificateToken trustedCertificate = DSSUtils.loadCertificateFromBase64EncodedString(trustedCertBase64);

        assertTrue(tstCert.isSignedBy(trustedCertificate));

        String crlBase64 = "MIICXTCBxgIBATANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUXDTI0MDgwODE0MDgyM1oXDTI1MDIwODE0MDgyM1owRTAhAgIB9xcNMjQwMzExMDkzMDEyWjAMMAoGA1UdFQQDCgEBMCACAQYXDTI0MDMxMTA5MzAxMlowDDAKBgNVHRUEAwoBATANBgkqhkiG9w0BAQsFAAOCAYEAf9otPW6s+UvUSIG2hhF/AC+P/2STuAF9d+0UACSxwmwZ63f+WcIYLaDOMG0E6jMl7JU77t+9QmLYexSC2a9fYH8ODj3tloR49H8KALFplVWNErfhS+nz3RH8eFoRn+rnsLn17kz7bbtyxdkZHwt93QO7Bjo/YPutKjmZgs3kmRsYNK0CxRw6ZRpCC9ZsyIAu22KIsgfiNG1N7UZiygdQoqJUyQrBMGYDIb7ESbLMzlaia/L4hqZ9AdhU/dxFOByL+JVAmTOzbWdGfRFfAil3KHxQMOiRnkcAPm40S2cqbxH17S0zLCY8S6JZBQQEWLOAwTRA+/ulMuWDZ0R1763dmGIKpzDVU8iRCUXuZXZfTun/pdPpToqfiZN3T7SsPKyolE3HL8HtNl7hAIWLZm9vLD8R3l6y+TuauEtDvCIPWF8J60KhL8Cp6uGRfkndGFlS1XtMW3A1LSgzlyocyUqZ8qXsYjphy3vMH7UN3EIBh65ZWapEDkj/39sCcbMGnv+I";
        CRLBinary crlBinary = CRLUtils.buildCRLBinary(Utils.fromBase64(crlBase64));
        CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, trustedCertificate);
        assertTrue(crlValidity.isValid());
        CRLToken crlToken = new CRLToken(tstCert, crlValidity);

        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
        Map<CertificateToken, List<CertificateTrustTime>> trustTimeByCertMap = new HashMap<>();

        Calendar calendar = Calendar.getInstance();
        calendar.set(2024, Calendar.AUGUST, 1);
        calendar.add(Calendar.YEAR, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 2);
        Date endDate = calendar.getTime();

        trustTimeByCertMap.put(trustedCertificate, Collections.singletonList(new CertificateTrustTime(startDate, endDate)));
        trustedListsCertificateSource.setTrustTimeByCertificates(trustTimeByCertMap);
        TrustAnchorVerifier trustAnchorVerifier = new TrustAnchorVerifier();
        trustAnchorVerifier.setTrustedCertificateSource(trustedListsCertificateSource);

        TimestampTokenVerifier timestampTokenVerifier = new TimestampTokenVerifier();
        timestampTokenVerifier.setTrustAnchorVerifier(trustAnchorVerifier);

        List<CertificateToken> certificateChain = Arrays.asList(tstCert, trustedCertificate);
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, certificateChain)); // no RevocationDataVerifier -> revocation check is skipped

        RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        timestampTokenVerifier.setRevocationDataVerifier(revocationDataVerifier);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, certificateChain));

        revocationDataVerifier.setAcceptRevocationCertificatesWithoutRevocation(true);
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, certificateChain));

        revocationDataVerifier.setAcceptTimestampCertificatesWithoutRevocation(true);
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, certificateChain));

        revocationDataVerifier.setAcceptTimestampCertificatesWithoutRevocation(false);

        timestampTokenVerifier.setRevocationDataVerifier(RevocationDataVerifier.createDefaultRevocationDataVerifier());
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, certificateChain));

        revocationDataVerifier.setProcessedRevocations(Collections.singletonList(crlToken));
        timestampTokenVerifier.setRevocationDataVerifier(revocationDataVerifier);
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, certificateChain));

        calendar.add(Calendar.YEAR, 2);
        Date futureDate = calendar.getTime();

        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, certificateChain, new Date()));
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, certificateChain, futureDate));

        trustAnchorVerifier.setUseSunsetDate(true);
        assertTrue(timestampTokenVerifier.isAcceptable(timestampToken, certificateChain, new Date()));
        assertFalse(timestampTokenVerifier.isAcceptable(timestampToken, certificateChain, futureDate));
    }

}
