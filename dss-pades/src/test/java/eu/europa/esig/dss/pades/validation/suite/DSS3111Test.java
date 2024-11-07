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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS3111Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-lt-b-extended-adbe.pdf"));
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEWjCCA0KgAwIBAgIQMo9kZ98qZ1djdKF45mVRATANBgkqhkiG9w0BAQsFADB1MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEoMCYGA1UEAwwfRUUgQ2VydGlmaWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMB4XDTIyMTIzMTIyMDAwMVoXDTI4MTIzMTIyMDAwMVowejEnMCUGA1UEAwweU0sgVElNRVNUQU1QSU5HIEFVVEhPUklUWSAyMDIzMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEMMAoGA1UECwwDVFNBMRswGQYDVQQKDBJTSyBJRCBTb2x1dGlvbnMgQVMxCzAJBgNVBAYTAkVFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnefs1HxAHAVoc7IabGuHXp4IrX1cC9hDa/lidDrodPiFF6y+8EAQEzP22LkrrxPVybrep3kodxFj4aVw4i6Q3c8EYyLE1gbbtrB4vTxeQIB2f2HGZ56Hr3uNj8JD+/iFvCe/5iAEso8dRVSX48kRRe8viAw6fnifXb+8iyff8y0VIcfSveNLiQXkYNB+TxQ0f/5+PCTIFez4pIzw8p0ZSIddUzldx2beyspNhAiju1cgy/bMULscv8j7YbFKZ4TmsUZHZuQc59MjaljderlwtV/tLBrg3OqR5nDq1Oi+aukjMNQX3FS76yXlPnwte2l3+0GrEGYst9yfpQk8c0xdcwIDAQABo4HgMIHdMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUuTR73sWfYH5L+mH3/RD0UAlC7egwHwYDVR0jBBgwFoAUEvJaPupWHL/NBqzx8SXJqUvUFJkwcwYIKwYBBQUHAQEEZzBlMB8GCCsGAQUFBzABhhNodHRwOi8vYWlhLnNrLmVlL0NBMEIGCCsGAQUFBzAChjZodHRwOi8vYy5zay5lZS9FRV9DZXJ0aWZpY2F0aW9uX0NlbnRyZV9Sb290X0NBLmRlci5jcnQwDQYJKoZIhvcNAQELBQADggEBACQXxeUVbmleiJ5NIN3f7Iv426xyTHXIxaxTh3T6MrLnVOBtCxa99jqKTG6Ljz1N6m/wE3GSnLVDL5Q77FqhJRasiyl3lJUjz82n0GL4L+C1JiW+n5dy6nUJUnSDHZhhD3LfnHxWLLfyRyWmDltXVHhU6Sgn2syAUrZ/aIzufY++iX0yoWYaMKhgfyz848r+nh+sK2pVp5rVT57D7x5+xFWDeyLQjhe9tHmXyGCyyjISChg+3cV+oQUY6VeMWS40+8E+rAHtxgvhN3YiSDGvOdNct6whea+daYyuJqu4emGCDHKa63iPSXhuD2c/AhiqSesCuRsRCEVNr/iLC5Il37Q="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        return trustedCertificateSource;
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean ltaLevelSigFound = false;
        boolean tLevelSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.PAdES_BASELINE_LTA.equals(signatureWrapper.getSignatureFormat())) {
                ltaLevelSigFound = true;
            } else if (SignatureLevel.PKCS7_T.equals(signatureWrapper.getSignatureFormat())) {
                tLevelSigFound = true;
            }
        }
        assertTrue(ltaLevelSigFound);
        assertTrue(tLevelSigFound);
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.PAdES_BASELINE_LTA.equals(signatureWrapper.getSignatureFormat())) {
                assertTrue(signatureWrapper.isSigningCertificateIdentified());
                assertTrue(signatureWrapper.isSigningCertificateReferencePresent());
                assertTrue(signatureWrapper.isSigningCertificateReferenceUnique());
            } else if (SignatureLevel.PKCS7_T.equals(signatureWrapper.getSignatureFormat())) {
                assertFalse(signatureWrapper.isSigningCertificateIdentified());
                assertFalse(signatureWrapper.isSigningCertificateReferencePresent());
                assertFalse(signatureWrapper.isSigningCertificateReferenceUnique());
            }
        }
    }

}
