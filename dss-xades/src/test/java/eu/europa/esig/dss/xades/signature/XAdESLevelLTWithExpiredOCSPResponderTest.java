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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelLTWithExpiredOCSPResponderTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private CertificateVerifier certificateVerifier;
    private CommonTrustedCertificateSource trustedCertSource;

    @BeforeEach
    void init() {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

        trustedCertSource = new CommonTrustedCertificateSource();
        trustedCertSource.addCertificate(getCertificate(OCSP_SKIP_CA));

        certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.addTrustedCertSources(trustedCertSource);

        service = new XAdESService(certificateVerifier);
        service.setTspSource(getSelfSignedTsa());
    }

    @Override
    protected DSSDocument sign() {
        Exception exception = assertThrows(AlertException.class, () -> super.sign());
        assertTrue(exception.getMessage().contains("Revocation data is missing for one or more certificate(s)."));

        certificateVerifier.setOcspSource(pkiDelegatedOCSPSource());

        exception = assertThrows(AlertException.class, () -> super.sign());
        assertTrue(exception.getMessage().contains("Revocation data is missing for one or more certificate(s)."));

        certificateVerifier.setCrlSource(pkiCRLSource());

        DSSDocument signedDocument = super.sign();
        assertNotNull(signedDocument);
        return signedDocument;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        CertificateVerifier offlineCertificateVerifier = getOfflineCertificateVerifier();
        offlineCertificateVerifier.addTrustedCertSources(trustedCertSource);
        validator.setCertificateVerifier(offlineCertificateVerifier);
        return validator;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return OCSP_EXPIRED_RESPONDER_USER;
    }

}
