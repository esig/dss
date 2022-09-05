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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.validationreport.jaxb.SADataObjectFormatType;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESSignDetachedCompactSignatureTest extends AbstractJAdESTestSignature {

    private DSSDocument originalDocument;

    private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
    private DSSDocument documentToSign;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    public void init() {
        service = new JAdESService(getCompleteCertificateVerifier());

        originalDocument = new FileDocument(new File("src/test/resources/sample.json"));

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setSigDMechanism(SigDMechanism.NO_SIG_D);
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();

        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        documentToSign = signedDocument;

        Exception exception = assertThrows(IllegalArgumentException.class, () -> super.sign());
        assertEquals("The payload or detached content must be provided!", exception.getMessage());

        signatureParameters.setDetachedContents(getDetachedContents());

        DSSDocument doubleSignedDocument = super.sign();
        documentToSign = originalDocument;

        return doubleSignedDocument;
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(originalDocument);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkMimeType(DiagnosticData diagnosticData) {
        boolean joseTypeSigFound = false;
        boolean joseJsonTypeSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            MimeType mimeType = MimeType.fromMimeTypeString(signatureWrapper.getMimeType());
            if (MimeTypeEnum.JOSE.equals(mimeType)) {
                joseTypeSigFound = true;
            } else if (MimeTypeEnum.JOSE_JSON.equals(mimeType)) {
                joseJsonTypeSigFound = true;
            }
        }
        assertTrue(joseTypeSigFound);
        assertTrue(joseJsonTypeSigFound);
    }

    @Override
    protected void validateETSIDataObjectFormatType(SADataObjectFormatType dataObjectFormat) {
        assertNotNull(dataObjectFormat.getMimeType());
        MimeType mimeType = MimeType.fromMimeTypeString(dataObjectFormat.getMimeType());
        assertTrue(MimeTypeEnum.JOSE.equals(mimeType) || MimeTypeEnum.JOSE_JSON.equals(mimeType));
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
