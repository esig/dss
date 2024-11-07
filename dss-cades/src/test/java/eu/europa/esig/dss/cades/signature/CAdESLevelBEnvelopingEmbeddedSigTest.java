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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelBEnvelopingEmbeddedSigTest extends AbstractCAdESTestSignature {

    private static DSSDocument originalDocument;

    private DSSDocument documentToSign;
    private CAdESSignatureParameters parameters;
    private CAdESService service;

    @BeforeEach
    void init() {
        originalDocument = new InMemoryDocument("Hello".getBytes(StandardCharsets.UTF_8));
        documentToSign = originalDocument;

        parameters = new CAdESSignatureParameters();
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setSigningCertificate(getSigningCert());
        parameters.setCertificateChain(getCertificateChain());
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setParallelSignature(false);

        service = new CAdESService(getOfflineCertificateVerifier());
    }

    @Test
    @Override
    public void signAndVerify() {
        DSSDocument signed = sign();

        CMSSignedData signedCMS = DSSUtils.toCMSSignedData(signed);
        assertFalse(signedCMS.isDetachedSignature());

        parameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        documentToSign = signed;

        DSSDocument doubleSigned = sign();
        CMSSignedData doubleSignedCMS = DSSUtils.toCMSSignedData(doubleSigned);
        assertTrue(doubleSignedCMS.isDetachedSignature());

        verify(doubleSigned);

        DSSDocument secondSignedDocument = CMSUtils.getOriginalDocument(doubleSignedCMS, getDetachedContents());
        signedCMS = DSSUtils.toCMSSignedData(secondSignedDocument);
        assertFalse(signedCMS.isDetachedSignature());

        documentToSign = originalDocument;

        verify(secondSignedDocument);

        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

        documentToSign = signed;

        doubleSigned = sign();
        doubleSignedCMS = DSSUtils.toCMSSignedData(doubleSigned);
        assertFalse(doubleSignedCMS.isDetachedSignature());

        verify(doubleSigned);

        secondSignedDocument = CMSUtils.getOriginalDocument(doubleSignedCMS, getDetachedContents());
        secondSignedDocument.setName("secondSignedDocument.p7m");
        signedCMS = DSSUtils.toCMSSignedData(secondSignedDocument);
        assertFalse(signedCMS.isDetachedSignature());

        documentToSign = originalDocument;

        verify(secondSignedDocument);
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(documentToSign);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        return parameters;
    }

}
