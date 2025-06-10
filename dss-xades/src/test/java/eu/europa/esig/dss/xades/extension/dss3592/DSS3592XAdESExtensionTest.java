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
package eu.europa.esig.dss.xades.extension.dss3592;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.extension.AbstractXAdESTestExtension;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class DSS3592XAdESExtensionTest extends AbstractXAdESTestExtension {

    private FileDocument documentToSign;

    private String signingAlias;
    private Date signingTime;
    private SignatureLevel originalSignatureLevel;

    @BeforeEach
    void init() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, -2);
        signingTime = calendar.getTime();
    }

    @Override
    protected FileDocument getOriginalDocument() {
        if (documentToSign == null) {
            documentToSign = super.getOriginalDocument();
        }
        return documentToSign;
    }

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        signingAlias = EXPIRED_USER;
        originalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;

        DSSDocument signedDocument = super.getSignedDocument(doc);
        documentToSign = toFileDocument(signedDocument);

        signingAlias = GOOD_USER;
        originalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
        signingTime = new Date();

        signedDocument = super.getSignedDocument(documentToSign);

        documentToSign = super.getOriginalDocument();

        originalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
        return signedDocument;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters =  super.getSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        return signatureParameters;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier completeCertificateVerifier = super.getCompleteCertificateVerifier();
        completeCertificateVerifier.setRevocationFallback(true);
        return completeCertificateVerifier;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        return getGoodTsaByTime(signingTime);
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return originalSignatureLevel;
    }

    @Override
    protected void checkOriginalLevel(DiagnosticData diagnosticData) {
        int bLevelCounter = 0;
        int tLevelCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.XAdES_BASELINE_B == signatureWrapper.getSignatureFormat()) {
                ++bLevelCounter;
            } else if (SignatureLevel.XAdES_BASELINE_T == signatureWrapper.getSignatureFormat()) {
                ++tLevelCounter;
            }
        }
        assertEquals(1, bLevelCounter);
        assertEquals(1, tLevelCounter);
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LTA;
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        int ltaLevelCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.XAdES_BASELINE_LTA == signatureWrapper.getSignatureFormat()) {
                ++ltaLevelCounter;
            }
        }
        assertEquals(2, ltaLevelCounter);
    }

    private FileDocument toFileDocument(DSSDocument document) {
        try {
            File originalDoc = Files.createTempFile("dss", document.getName()).toFile();
            try (FileOutputStream fos = new FileOutputStream(originalDoc); InputStream is = document.openStream()) {
                Utils.copy(is, fos);
            } catch (IOException e) {
                throw new DSSException("Unable to create the original document", e);
            }
            return new FileDocument(originalDoc);

        } catch (IOException e) {
            fail(e);
            return null;
        }
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
