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
package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCECAdESDoubleLTAWithCustomArchiveManifestNameTest extends AbstractASiCEWithCAdESMultipleDocumentsTestSignature {

    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentsToSign = new ArrayList<>();

    @BeforeEach
    void init() throws Exception {
        documentsToSign.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT));
        documentsToSign.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeTypeEnum.TEXT));
        documentsToSign.add(new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY, "emptyByteArray"));

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();
        filenameFactory.setArchiveManifestFilename("ASiCManifest.xml");
        getService().setAsicFilenameFactory(filenameFactory);

        // default name for Archive Manifest is used
        DSSDocument signedDocument = super.sign();

        ASiCWithCAdESSignatureParameters extensionParameters = new ASiCWithCAdESSignatureParameters();
        extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);

        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                getService().extendDocument(signedDocument, extensionParameters));
        assertEquals("An archive manifest file within ASiC with CAdES container shall match the template " +
                "'META-INF/ASiCArchiveManifest*.xml'!", exception.getMessage());

        filenameFactory.setArchiveManifestFilename("ASiCArchiveManifestAAA.xml");
        getService().setAsicFilenameFactory(filenameFactory);

        extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        return getService().extendDocument(signedDocument, extensionParameters);
    }

    @Override
    protected void checkExtractedContent(ASiCContent asicContent) {
        super.checkExtractedContent(asicContent);

        boolean asicArchiveManifestFound = false;
        boolean asicAAAArchiveManifestFound = false;
        assertEquals(2, asicContent.getArchiveManifestDocuments().size());
        for (DSSDocument document : asicContent.getArchiveManifestDocuments()) {
            if ("META-INF/ASiCArchiveManifest.xml".equals(document.getName())) {
                asicArchiveManifestFound = true;
            } else if ("META-INF/ASiCArchiveManifestAAA.xml".equals(document.getName())) {
                asicAAAArchiveManifestFound = true;
            }
        }
        assertTrue(asicArchiveManifestFound);
        assertTrue(asicAAAArchiveManifestFound);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        assertEquals(3, diagnosticData.getTimestampList().size()); // sigTsts + 2 arcTsts
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        List<DSSDocument> retrievedDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
        for (DSSDocument document : documentsToSign) {
            boolean found = false;
            for (DSSDocument retrievedDoc : retrievedDocuments) {
                if (Arrays.equals(DSSUtils.toByteArray(document), DSSUtils.toByteArray(retrievedDoc))) {
                    found = true;
                }
            }
            assertTrue(found);
        }
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentsToSign;
    }

    @Override
    protected ASiCWithCAdESService getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
