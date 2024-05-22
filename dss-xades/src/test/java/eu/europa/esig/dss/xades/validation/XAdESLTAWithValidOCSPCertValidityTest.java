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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLTAWithValidOCSPCertValidityTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-lta-valid.xml");
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
        certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIID/zCCAuegAwIBAgICBLAwDQYJKoZIhvcNAQELBQAwUDETMBEGA1UEAwwKZWUtcm9vdC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTIwMDkxMTEzMzgyN1oXDTIyMDcxMTEzMzgyN1owUTEUMBIGA1UEAwwLZWUtZ29vZC10c2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5m6K2f2zh7ZCyqCFHE6EVs5mz9eE7nS7mL/KkDxbByk83jNq0Dl+Lcfi962UoZ2JyJ0sh1dzS6r3MQm45Qyt7qSAOKZHZEc2uLJYikSEl5q+SlvRKVSOtdItESFzoyyjUccGhNKmFk6073ny6KmEY9VgYNAQLx3U4/GdDn8XGN9OWbNxGFlrfQS/0O2ScXeQsyRC7SGehGROK6vVaEJDS2sgsnAvpecgHxRcKSD3FB/YLZdILgShahUrK11/7YDS1rL/qUfoFezNu7iYrfOWkooso+nZXglLP9gZLGQA2I5wyIRV2yKodO110djd6WfIfdGjRSrrup38j+YycjVAECAwEAAaOB4TCB3jAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL2VlLXJvb3QtY2EuY3JsME8GCCsGAQUFBwEBBEMwQTA/BggrBgEFBQcwAoYzaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3J0L2VlLXJvb3QtY2EuY3J0MB0GA1UdDgQWBBQ8vC+mcyr+mPirXCf0/Qci8MSvhzANBgkqhkiG9w0BAQsFAAOCAQEANeKxwuAm9ni69tkdz5/Bqgp1xdagK0SZJMWP5Qr69uTSPzzR/SpG2FF4VD2Jk41qTUL2XyAY8kKh1uwTW7GINbaNoFF4XvVZn0PISwGBlkRNo5fGeCc9DmkUqHEWn+OZ4psYkkS96Lzke8OZPnqu/2xV9Z8Rd4O7DMuMDLkq18okqJ5QloMcylmaeXWQl+T+S3DhEZ+UrZJihA9fyW4zOkKPmw2+c7Y0lsgVxZIGksQWxFGsk52exYw7YaSG3rm0Sg5stNzfrpMwhAPPfDi0ltkgSmAzmCnaokU9ZZfbBVJKD0lyLirnESs2AplX75sNG8aUMJU6AblMbQUndsigiQ=="));
        certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjAwODExMTMzODQ2WhcNMjIwODExMTMzODQ2WjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbPNNfnt/DLFBCITlbVs/p9zjEZnwMCxYA9XjGwY866otqZ9QPuDwV+gimlPdsZo41ph8tNNneLgwwm8Ju2eTY94uRneUZAkLK0FZA0kGg6uPtDKlUkVRzYcRkfAzUB6D3hgp3yI72EF3TfZ3KKEr6h7IBVmKI7fhF5DGBZ/kXcPVmx+2qgTAQQWjLFSxaAbAozWX0lqF6mb5FbMhI1nYsI3Dfri1ne6JB2FoiUUclQYbHO/AkVoCkQ7mjzkRz5Wg25CQIC9Ry40d9JPkT3s6BDzNB7QmOXuP1ebw3P13LOzvjOgP5pByePMylIHOHhxKx7nKNtQUDPefyLzk6Y5IhAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUeiKvMxpYImeWH2ooAIfMB0aWL9IwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAYxuCQLquCbVG4Q+2IZjfpCf5sOGhrESLsoZrlXX+8P+3FJ0yqLxQwkLe2Q55CbvPg39kdjtW8V1/ZrMuV00YWDSwhSQCuUH9id/2gWZ+TA6J83nTnPmGcyAnLChhG5yuZZZxPy9fzhZRwA4O91VFrd/5aXZ0fBsfhOPc/t5J0vPbbv+wkCj+A/gQk5wmne9u53brZI39aoqZmYFC5JiprI5f8cgM7s94Z7LUg4k9vlNiw3Ovo5oHEui9j6skIu5yWqmC+7d60KIRhHgwxm/plbNr9Ed2O+xVn1G0tK7CuQDoKK/n16FnTBB3xHY2u/nwMKL0MGKg5+n+iwYi7aC6Yw=="));
        return certificateSource;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setOcspSource(getOCSPSource());
        validator.setCertificateVerifier(certificateVerifier);
        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_AND_REVOCATION_DATA);

        return validator;
    }

    private RevocationSource<OCSP> getOCSPSource() {
        DSSDocument ocspResponse = new InMemoryDocument(Utils.fromBase64("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"));
        return new ExternalResourcesOCSPSource(ocspResponse);
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        assertNotNull(signingCertificate);

        List<CertificateRevocationWrapper> revocationData = signingCertificate.getCertificateRevocationData();
        assertEquals(1, revocationData.size());

        boolean embeddedOCSPFound = false;
        for (RevocationWrapper revocationWrapper : revocationData) {
            assertEquals(RevocationType.OCSP, revocationWrapper.getRevocationType());

            if (RevocationOrigin.INPUT_DOCUMENT.equals(revocationWrapper.getOrigin())) {
                embeddedOCSPFound = true;
            }
        }
        assertTrue(embeddedOCSPFound);
    }

}
