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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEXAdESMultiFilesLevelBDoubleSignatureTest extends AbstractASiCEWithXAdESMultipleDocumentsTestSignature {

    private static final List<DSSDocument> ORIGINAL_DOCS = new ArrayList<>();

    private ASiCWithXAdESService service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentToSigns = new ArrayList<>();

    @BeforeEach
    void init() throws Exception {
        service = new ASiCWithXAdESService(getOfflineCertificateVerifier());

        ORIGINAL_DOCS.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT));
        ORIGINAL_DOCS.add(new FileDocument("src/test/resources/manifest-sample.xml"));
        ORIGINAL_DOCS.add(new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY, "emptyByteArray"));

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
    }

    @Override
    protected DSSDocument sign() {
        documentToSigns = ORIGINAL_DOCS;

        DSSDocument firstSignedDocument = super.sign();
        assertNotNull(firstSignedDocument);

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MILLISECOND, 1);

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(calendar.getTime());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        documentToSigns = Collections.singletonList(firstSignedDocument);

        DSSDocument secondSignedDocument = super.sign();
        assertNotNull(secondSignedDocument);

        documentToSigns = ORIGINAL_DOCS;

        return secondSignedDocument;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signatureOne = diagnosticData.getSignatures().get(0);
        SignatureWrapper signatureTwo = diagnosticData.getSignatures().get(1);
        assertFalse(Arrays.equals(signatureOne.getSignatureDigestReference().getDigestValue(),
                signatureTwo.getSignatureDigestReference().getDigestValue()));
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
            assertEquals(3, Utils.collectionSize(signatureScopes));
        }
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        for (String signatureId : diagnosticData.getSignatureIdList()) {
            List<DSSDocument> retrievedDocuments = validator.getOriginalDocuments(signatureId);
            for (DSSDocument document : documentToSigns) {
                boolean found = false;
                for (DSSDocument retrievedDoc : retrievedDocuments) {
                    if (Arrays.equals(DSSUtils.toByteArray(document), DSSUtils.toByteArray(retrievedDoc))) {
                        found = true;
                    }
                }
                assertTrue(found);
            }
        }
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentToSigns;
    }

    @Override
    protected MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
