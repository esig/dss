package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

public class RevocationDataLoadingStrategyTest {

    private static final CertificateToken CERTIFICATE = DSSUtils.loadCertificateFromBase64EncodedString("MIIEIDCCAwigAwIBAgIBFzANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjAwMzIyMDY0MjQzWhcNMjIwMTIyMDY0MjQzWjBYMRswGQYDVQQDDBJnb29kLXVzZXItY3JsLW9jc3AxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIwlifsMcZPcpSvwdXrVXy++7pgMXW/wlT4NnC2HyADRgI5+38U626ljtbOiAYo3oumH9tliXDIZyyT6qcMvDajGDLHNZK4W7xJNpt1hoDt/AIMH18368G3Y2wAdIFP1DfZlCp9QgnUCPcCFcdVWQsP/qwIa2uJwlzcaDDYmKNzg+tFrxB2XfcxHVZoR3b7+5dX2VuNWHOzgosiQyejjBfWf2HNU1JAbakoCa1UET8Ro5Ldu+/Mxn9qQfQKdvpItvXHEBBuqznIw79hoyJd3tT4v0YItl6gMwvZAWpiU88LsN9tGE4Zvy5fOsQDoXsv2fm+A18kiPHOKgjxx0CghffsCAwEAAaOB/zCB/DAOBgNVHQ8BAf8EBAMCBkAwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL2dvb2QtY2EuY3JsMIGHBggrBgEFBQcBAQR7MHkwOQYIKwYBBQUHMAGGLWh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L29jc3AvZ29vZC1jYTA8BggrBgEFBQcwAoYwaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3J0L2dvb2QtY2EuY3J0MB0GA1UdDgQWBBSKLPGXPCTge5Oudi6nLu9UL4Y8UjANBgkqhkiG9w0BAQsFAAOCAQEAKtMfbZXKYQlbI88e14xUgqgOinmgIoaDPGA6HUJKy4WCPwTcvip69N1hSk92MEapLZWsBcqssd4OoZezkdH/pI4tPP6ccUQ18Lh+DffRx/J4ayj/9jk+eM1LLUMsZdl0dDvWOhs1lR+ltcMvhdbtxRCmdSWO7jYtDuufxCFkZRzisLFabTxVZ7r1CsP859pNKHygls1UfQdf/A9H5afT/1gwPSl3/1m0XCUy2J0yJkMOTOyamg7bMcZeMPjYdIP9qdn4JKsoKaYpaCDb2Cz1dkqOi4/iulxUy5LlPQk0aWva7bivOmoUB/60ITTadNyX2YmzwyVCotY5tDme8IgVaA==");
    private static final CertificateToken ISSUER = DSSUtils.loadCertificateFromBase64EncodedString("MIID6jCCAtKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjAwMzIyMDY0MjM3WhcNMjIwMTIyMDY0MjM3WjBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD0cdv4KehxUUp9H44wdj3lBt8xUiSb4TgFOdVI4dbcIL2nDveaN2G2ZA495YVf4v/jx3a4kN2VAw0Qzvjy4lY+d96LR5VEZdN7lB4RtQJJw623Cgoeu4cXjqGIqT/tHs4tOau+80U6CaIo05TyRhrzWlCOEYjdRU3L31bGKe9mVJlobNKunGB2CvBp2cWtx8y8OBJ4QdDchI6kpD2dO9llQqcT+4NkPxa4uY+dcG5MQX7hwHENixRkXGWsi1WsIS7VN1Nh1GRAOYk216uMlrKrATsbWc4De4KZEjgYJ13jSlpWNYq8vmd8GCYazpLiNIlQ05wfNvunjIGnnlICOWcXAgMBAAGjgdQwgdEwDgYDVR0PAQH/BAQDAgEGMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NybC9yb290LWNhLmNybDBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUHMAKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9yb290LWNhLmNydDAdBgNVHQ4EFgQUZnBMwCvQf2LqNeVWZgsRXBbDk8swDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAEaQgSSNp24JamgFcjBSgnyFiL6NfgMYTr+8HcICKKLLle3tT5/wYigbefQA2G8iodbwpA3YDP5yEadGDsGT15ginRuZp8JJZ/p9t7UNuZTEuC1Bx9OXqRF+MnXjNyN9h18colO170LNynI/qAxxjV/bgIuZWNm+ZJ+OIVwRE2mVbrM8/sellNn2t18DFe6X6QQjseq6ZaO2Sb4SAdQ0BfnELkAfawzvk1a6w/6H7xKF0FecAt2ExxTz9xdqE6jdlUrTfhkFGhdKRTQoOeN0bmXMM8r5HZKf9zxBFqLjYThTkDIXe82Yin7Idy1V87p/hft7MtHW7Br8A+2CpP4vSLg==");

    private static final String OCSP_RESPONSE = "MIIIjQoBAKCCCIYwggiCBgkrBgEFBQcwAQEEgghzMIIIbzB8ohYEFOiMLQUIIwmNgYIMuTyzes3nPv2CGA8yMDIxMDMyMjEzNTA1N1owUTBPMDowCQYFKw4DAhoFAAQULFsRCayq2JfWOw4G6WfL7rWAHDQEFGZwTMAr0H9i6jXlVmYLEVwWw5PLAgEXgAAYDzIwMjEwMzIyMTM1MDU3WjANBgkqhkiG9w0BAQsFAAOCAQEAswOCFCHSZGbRiH+g5kpzgGYsdXMnBj8tavJTQaChpHB8ju9VziRPUJMT2Wr3m1zwcGjYfw4wbA4eJOidW+o5txpQSrtboyRTzHkoRZ0Nju21vju3Jbd6BlgtbGRLNMJOB35AyqmEdyq/UQpQNoNFeVDC7iXekBTO2gzjhu3mdwy42BWyJnKy9akv+dALLTSzEW97psIiv7SF29Pw5Bkje8Sa86GZ1F40iBLDORvR2h/9k2ufPNq7RRFT+RJDmYC9DhWAYcT6hr2OOugNdD0fDuM9Qf+JGc0CjVXuHc2Xsb2eg9qlQCvL+VPUIjNUiIEDi9vss017xcekez8/j8rUT6CCBtkwggbVMIIDdjCCAl6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjAwMjIyMDY0MjM2WhcNMjIwMjIyMDY0MjM2WjBUMRcwFQYDVQQDDA5vY3NwLXJlc3BvbmRlcjEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvV0a4KvO8UTl5LwlWG6EAUClApQEaU4fBEvzxkltd7wHtkPGaiLGsKB65UjsAVyDqdPYJMv32vy3wp3Q4sx2b+Hc8QOpBCiTciRo/UzKZsVG9KiD+ZN0LJLG2kS6q7EMc04AIRDJ7/tBp1AxWStX4goXzGrPMyx+4VjlBDC7jBWjDgta+YouE9EFWM6TpySMbg9O75OHSpfXJIohTS8yEeR35Dnr+7Cy08azEP877jl952M55RdawotmlUt9JSYmcFvKdUhj8zTkotulZTHvDnjBid8dgvUJ89Cj0puj+4XakiI6gikJDGz8mesZh5eRLMIZW7fKNIpWC1WgcDO2zwIDAQABo1owWDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwkwHQYDVR0OBBYEFOiMLQUIIwmNgYIMuTyzes3nPv2CMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQELBQADggEBAIbCsDfV9NUH6PJtNGVZPLkTFJy9CcvVkkbzs72Jmgz44S2cgjxOm7aryvn0arZN2wfvWR7sjE4dtsr4DapMesxlnLvhPiQ5adlcbDwRdY/2sUd0Y3XOhR1DhkM6qDwYJkUqLNU54L4Ig2abQFZA/IG8b++KeljZ6stJlJPOxjbXM3M+PnvUJ5E2UrOT+E8oX/9JGjR2t7bq726z5Ina5uUmoYW/wQrbZgG8GZkWs+Tct4dJhAlxtpaSVTPPC9XA+kVP/bKE7rW2xWS3oZJJ8w4wlc1eXj20bL9qVuTveyuDvQUaYD9Njqi58NDOkG8M2zSPmmd34S2OPJQeBjpduUowggNXMIICP6ADAgECAgEBMA0GCSqGSIb3DQEBDQUAME0xEDAOBgNVBAMMB3Jvb3QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTAeFw0yMDAyMjIwNjQyMzZaFw0yMjAyMjIwNjQyMzZaME0xEDAOBgNVBAMMB3Jvb3QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALuvci6sFDaGy17gcaPZuDwxq0wCP1tC8y/gtO3SV4T09u7LCpD1R73sRQ7cUx86A0UR1aBeaU/iZupWIQ/nJ2jVI6quac+D+7WdMJdkLxeE1vQD62AkvAFgQ24h3JscJxpmKfYuLw4q9N5L5PiIxcvAKrqI8gDVRLRU8vGuUcWsnT7Ndoq1anqm5ohCIXFxhaAyzeJ5Zl5Z1zj/wV6Vgs8DhxLD5P7PrV7X2+beIQvFh46tiGYztkj4X6uPNu2gg/eoVGuh1oxz0pJLdXc13tGdg71961e4LgsfLwtYbJio3FRqDp0M+igwRqGPdmRrl/uh9fEdwTrPPl32zgpgdqECAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQQKyWPBGQyWaF37GDME7cScnoAWjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAQB6qf9UYnr1h54Iv4QBvk3fSQigDhh02xjfIJZoaFTeITLM+ZEHpLgRSIWYR9qx/FOFG9movBIIOKTfOnIt+Iqt0/kBRHWk6KuE5xlSQn3Volm0BXPFJaGw8iza3HjFAdeZCkhArUkVYb7GOQqYXnPLiE2ltdzlRTLd5s07vQlUYcJlFf3zZ2+fFd2Zmb+bBEZHiKWRu2RXss8L8VRYfC1NmXNFaemby1MVu8HNoedldC9rbkV9lMphk0t6MnVpbmRW+laEjfhlrjvT2u0eFY6WTCOPm9X/8V1AUuTmr+9C64rigI4AQ8pequlyLc24ekE8bz+oBqhWiNTjVr9dJOPF";
    private static final String CRL = "MIIB3DCBxQIBATANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUXDTIxMDMyMjEzNDIzMVoXDTIxMDkyMjEyNDIzMVowRDAgAgEMFw0yMTAxMjIwNjQyNDBaMAwwCgYDVR0VBAMKAQEwIAIBExcNMjEwMTIyMDY0MjQyWjAMMAoGA1UdFQQDCgEGMA0GCSqGSIb3DQEBCwUAA4IBAQCJmVmEwmZaikxmjwyD/TEAaXJ06AJqhLFlfCq6/cHbhTZZ1GRsl13CXwmyLBDDZY52aS/ZDmYKb+v58RXd2KEZOhaPoxW4FLOJvdM0z9ywsYomxkchqz1GS7yNRCm13+XsTUEuK6JdSMLRn2Av6An8jyyXVzMO0kX29rr3mwvSso1fpZ/LwKi3m9f+jxVe65iZfjxDa5gqbv5ENOvT40HHNC9SSFHZLH5db5LIpr7ED/f8FgxWiE6MSp1I1sDdOCy1xt3aKERxAIVkwolwplx65I6pT15ykDAFvJMTMxyMGCDF8iajAbk3O62TPiaU/ncolBdBVxGZKXKEtMP50Eus";

    private static OCSPToken ocspToken;
    private static CRLToken crlToken;

    private OCSPSource ocspSource = new MockOCSPSource();
    private CRLSource crlSource = new MockCRLSource();

    @BeforeAll
    public static void init() throws Exception {
        final OCSPResp ocspResp = new OCSPResp(Utils.fromBase64(OCSP_RESPONSE));
        BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        SingleResp latestSingleResponse = DSSRevocationUtils.getLatestSingleResponse(basicResponse, CERTIFICATE, ISSUER);
        ocspToken = new OCSPToken(basicResponse, latestSingleResponse, CERTIFICATE, ISSUER);

        final CRLBinary crlBinary = new CRLBinary(Utils.fromBase64(CRL));
        final CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, ISSUER);
        crlValidity.setIssuerToken(ISSUER);
        crlToken = new CRLToken(CERTIFICATE, crlValidity);
    }

    @Test
    public void ocspFirstThenCrlTest() {
        RevocationDataLoadingStrategy revocationDataLoadingStrategy = new OCSPFirstRevocationDataLoadingStrategy();
        revocationDataLoadingStrategy.setOcspSource(ocspSource);
        revocationDataLoadingStrategy.setCrlSource(crlSource);

        RevocationToken revocationToken = revocationDataLoadingStrategy.getRevocationToken(CERTIFICATE, ISSUER);
        assertNotNull(revocationToken);
        assertEquals(RevocationType.OCSP, revocationToken.getRevocationType());

        revocationDataLoadingStrategy.setOcspSource(null);
        revocationToken = revocationDataLoadingStrategy.getRevocationToken(CERTIFICATE, ISSUER);
        assertNotNull(revocationToken);
        assertEquals(RevocationType.CRL, revocationToken.getRevocationType());

        revocationDataLoadingStrategy.setCrlSource(null);
        revocationToken = revocationDataLoadingStrategy.getRevocationToken(CERTIFICATE, ISSUER);
        assertNull(revocationToken);
    }

    @Test
    public void crlFirstThenOCSPTest() {
        RevocationDataLoadingStrategy revocationDataLoadingStrategy = new CRLFirstRevocationDataLoadingStrategy();
        revocationDataLoadingStrategy.setOcspSource(ocspSource);
        revocationDataLoadingStrategy.setCrlSource(crlSource);

        RevocationToken revocationToken = revocationDataLoadingStrategy.getRevocationToken(CERTIFICATE, ISSUER);
        assertNotNull(revocationToken);
        assertEquals(RevocationType.CRL, revocationToken.getRevocationType());

        revocationDataLoadingStrategy.setCrlSource(null);
        revocationToken = revocationDataLoadingStrategy.getRevocationToken(CERTIFICATE, ISSUER);
        assertNotNull(revocationToken);
        assertEquals(RevocationType.OCSP, revocationToken.getRevocationType());

        revocationDataLoadingStrategy.setOcspSource(null);
        revocationToken = revocationDataLoadingStrategy.getRevocationToken(CERTIFICATE, ISSUER);
        assertNull(revocationToken);
    }

    private class MockOCSPSource implements OCSPSource {

        @Override
        public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
            if (CERTIFICATE.equals(certificateToken) && ISSUER.equals(issuerCertificateToken)) {
                return ocspToken;
            }
            fail("Not implemented!");
            throw new IllegalArgumentException("Not implemented!");
        }

    }

    private class MockCRLSource implements CRLSource {

        @Override
        public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
            if (CERTIFICATE.equals(certificateToken) && ISSUER.equals(issuerCertificateToken)) {
                return crlToken;
            }
            fail("Not implemented!");
            throw new IllegalArgumentException("Not implemented!");
        }

    }

}
