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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.validation.identifier.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESTripleSignatureWithUserFriendlyIdentifierTest extends AbstractXAdESTestSignature {

    private DSSDocument originalDocument;

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private Date signingTime = new Date();

    @BeforeEach
    void init() throws Exception {
        originalDocument = new FileDocument(new File("src/test/resources/sample.xml"));
        service = new XAdESService(getOfflineCertificateVerifier());

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss");
        String timeString = sdf.format(signingTime);
        signingTime = sdf.parse(timeString); // remove millis
    }

    private XAdESSignatureParameters initSignatureParameters() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(signingTime);
        calendar.add(Calendar.MILLISECOND, 1);
        signingTime = calendar.getTime();

        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = originalDocument;
        signatureParameters = initSignatureParameters();
        DSSDocument signed = super.sign();

        awaitOneSecond();

        documentToSign = signed;
        signatureParameters = initSignatureParameters();

        DSSDocument doubleSigned = super.sign();

        awaitOneSecond();

        documentToSign = doubleSigned;
        signatureParameters = initSignatureParameters();

        DSSDocument tripleSigned = super.sign();

        documentToSign = originalDocument;
        return tripleSigned;
    }

    @Override
    protected TokenIdentifierProvider getTokenIdentifierProvider() {
        return new UserFriendlyIdentifierProvider();
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(3, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
        super.checkSignatureIdentifier(diagnosticData);

        boolean firstSigFound = false;
        boolean secondSigFound = false;
        boolean thirdSigFound = false;
        for (String sigId : diagnosticData.getSignatureIdList()) {
            if (sigId.endsWith("_2")) {
                secondSigFound = true;
            } else if (sigId.endsWith("_3")) {
                thirdSigFound = true;
            } else {
                firstSigFound = true;
            }
        }
        assertTrue(firstSigFound);
        assertTrue(secondSigFound);
        assertTrue(thirdSigFound);
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
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

}
