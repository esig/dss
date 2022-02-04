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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS2601Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-2601.pdf"));
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIFRTCCAy2gAwIBAgIBATANBgkqhkiG9w0BAQsFADAqMSgwJgYDVQQDDB9FdXJvcGVhbiBDb21taXNzaW9uIFJvb3QgQ0EgLSAyMB4XDTE2MTAwNDExMjExN1oXDTQ2MTAwNDExMjExN1owKjEoMCYGA1UEAwwfRXVyb3BlYW4gQ29tbWlzc2lvbiBSb290IENBIC0gMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL4JYI9CBISZuBOBknpxCRX306sYm4tQPm5H2l5f4fDESYbthbv8FEOFUPu/uh/L5FuCsPgjDkHp6lQqfWV0QG8550pLWI82B5EgE/tN0F4Iwq5OVzOwK+qkHpcXLwxZATNYmfgTGAb2mcvVZ8ZkhL4cm6fWqjGzpX9av4R1uqRMKxm/0xuUXx37034g1/fMvzZ3V4rLGOwEGluagitBcZhpXXnAFZAu6QF07dokW7vgOOm392TlVgJrv94qN73gMfl/CGQd8Sb3t75HhYQ9kGyXEkFzOyPvwBlvV6hCOvElU+2u/HPYYz5lrC0u3MHPos16XF5/XJ7M/H9DDtA5mv3B9xO+/67fdaMyXaUJzoiE3decIUgLQC0Qh5hNs1kdkBnufmYRvpe9sUHWCsk39cNwVX+vp8EKDjtkiQbFuYIqvFckBbm7AcJlUt4jj6SJHVhECM4SCVd+oUtsaTStKUrrVjvuXgzN65qfzafesiaimXYWD60gRp7OoCiN9QwkCiRD1Iqs9irEE2DrIz15suuTb2+esrKciiIqyENUeYQolLhPvfdsZhdrtlFsDxM+/IPl7xz0V66kA97FtQuiVFOrZaj1YdjSpSfUlscpUfJHMebdd36zQ85oFyGERx7VHpjwE8bw4w4nDfnCKsz4xe7gZZX3CaKBCng6F4KiVXZHAgMBAAGjdjB0MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFC+klbkQluW624UvF9NUjFzbrNNXMB8GA1UdIwQYMBaAFC+klbkQluW624UvF9NUjFzbrNNXMBEGA1UdIAQKMAgwBgYEVR0gADAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAFPypMzasOt82j0geV8hJOopri91Jc1d/fpc6mlubXb8E/scI9qqWQVUMlqiJkCyZl1TVis0bCPFvSlDl/hhwS5vnC0rBmCTXXEEsQmsEasw/IR4e7bNAF+l/pPmggh7u+Y00kjYt1XweA2Of/+xf4nAk3HiX02IToHmY/Y4nlLP3bt1oac01Zv7sHPogmQrFFAvuoC4k+e6vJP0XveSp/vBpfKrdCNjnViZ3J8gUzrRowi10U812/A5NtZFvKOYXPTFi4vznYMmZsfgejUab5f/j+ycgrFlsvw8vhYwWsJhWM/oPVNGnfYusa/8aovhwOiCe6lnn3o2jIASIPy6ReSzqZpqImKmUGdARWSFCJw4NX1m2dg4GnMjSlWFv5fEnyF0wZlqniarr2TsRek85N6vIaklzc0kA5gNgWLTxXMbr8rNta1RtXcN+SH8QgQ8CKgjbq4PSD/WPoOxRcZemGTXBdgxhTjZJgwaQU4L810bScOcQ9cI1QB0/Iq+7fQOg9xIl3mvSoEhnP36Dr3uoi+yem1UhnjU9DHE0uKYpHjlHXP6LHvjfQZyS3ba3S0/nYsVf24b4UEja3PehnHhdzyJx/cHRJpNT5ibC5pZWL61QgOrDHuSBQnEQUMmYwNoqS+HQvu532NjlSfG6ffmDuEkGuBMM1jYgTqhM3BGMuf+"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEWjCCA0KgAwIBAgIQCrITQgwdM4hfdZRtSgVwszANBgkqhkiG9w0BAQsFADB1MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEoMCYGA1UEAwwfRUUgQ2VydGlmaWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMB4XDTIwMTIzMTIyMDAwMVoXDTI1MTIzMTIyMDAwMVowejEnMCUGA1UEAwweU0sgVElNRVNUQU1QSU5HIEFVVEhPUklUWSAyMDIxMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEMMAoGA1UECwwDVFNBMRswGQYDVQQKDBJTSyBJRCBTb2x1dGlvbnMgQVMxCzAJBgNVBAYTAkVFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwmZuFcXZ3UGPjIEX0mldGSTiUxMcfG8Fh0f4VlAg6aN/buuRVaEpwrS7UfTD/HF7JojcJidFf7wTBd+B52oqYhya7rT/d11exeDtwIZpymksqC+F8bWoleJ3HkSByyGfuGcGGSnowaCjcZqTT2YCT40PdfJfPIaUqobjNC9idFP/FOzgHWu8hUiOAixZ+X22r0CVgTnNW0/xiaRPq/PgpgDAsxlYDABonFKiCEfHyK5T1rjV585lfwWBcPo5jnI9tIyT3fSB06QZ0i4rmFcPli/0XvyHrGNNpJNPJ9lb9d0VhcPwktoDr2nBFgBzpjRufwVPjQCBuDVidkuMEjLOTwIDAQABo4HgMIHdMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUEDIBfAAH5r+iCV+irQKE3Tk2/h8wHwYDVR0jBBgwFoAUEvJaPupWHL/NBqzx8SXJqUvUFJkwcwYIKwYBBQUHAQEEZzBlMB8GCCsGAQUFBzABhhNodHRwOi8vYWlhLnNrLmVlL0NBMEIGCCsGAQUFBzAChjZodHRwOi8vYy5zay5lZS9FRV9DZXJ0aWZpY2F0aW9uX0NlbnRyZV9Sb290X0NBLmRlci5jcnQwDQYJKoZIhvcNAQELBQADggEBACnGDxtyt0EmeLyGhwW01/rg6q9KStXW65qwNnTdW7QpY+3Q8Oc64zJAAOAkfcaSa1BqlJmO7QMkSnpeEa5AH//48bdfZ0RYRGnEpoqq6L5Qi6iCHBduRDxrea0bR7s/UaIB9PMR6jNU7Y4hSlAZCTxZvsuOwgbYzU1kJipc5mh4nSDU3qyL7vPefgQAgLMOhMI78ZFSHGxGJf+BNOaHzD4IYBRd81Facnr5+hfD2gNFPcuf9DPFVinKUG9c4XuKj6V30fGBBZoSfju53Jk6/aGfKwKWLpN13Sh4RMb+KL2S/mDIMKRVCst901nPorgq58Bjd/zm6CptMqABrIpGRl8="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        return trustedCertificateSource;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setValidationTime(DSSUtils.getUtcDate(2021, 10, 11));

        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        DSSDocument ocspResponse = new InMemoryDocument(Utils.fromBase64("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"));
        ExternalResourcesOCSPSource ocspSource = new ExternalResourcesOCSPSource(ocspResponse);
        certificateVerifier.setOcspSource(ocspSource);
        validator.setCertificateVerifier(certificateVerifier);
        return validator;
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        assertNotNull(signingCertificate);

        List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
        assertEquals(2, certificateRevocationData.size());

        boolean internalOcspFound = false;
        boolean externalOcspFound = false;
        for (RevocationWrapper revocationWrapper : certificateRevocationData) {
            if (RevocationOrigin.INPUT_DOCUMENT.equals(revocationWrapper.getOrigin())) {
                internalOcspFound = true;
            } else if (RevocationOrigin.EXTERNAL.equals(revocationWrapper.getOrigin())) {
                externalOcspFound = true;
            }
        }
        assertTrue(internalOcspFound);
        assertTrue(externalOcspFound);
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        // skip (overlap detected)
    }

}
