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
package eu.europa.esig.dss.asic.cades.signature.asics;

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
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSCAdESLevelBCustomPackageNameTest extends AbstractASiCSWithCAdESMultipleDocumentsTestSignature {

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
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();
        filenameFactory.setDataPackageFilename("inner-container.TXT");
        getService().setAsicFilenameFactory(filenameFactory);

        Exception exception = assertThrows(IllegalArgumentException.class, () -> super.sign());
        assertEquals("A data package filename within ASiC container shall ends with '.zip'!",
                exception.getMessage());

        filenameFactory.setDataPackageFilename("inner-container.ZIP");
        getService().setAsicFilenameFactory(filenameFactory);

        return super.sign();
    }

    @Override
    protected void checkExtractedContent(ASiCContent asicContent) {
        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals("inner-container.ZIP", asicContent.getSignedDocuments().get(0).getName());
        assertTrue(Utils.isCollectionNotEmpty(asicContent.getContainerDocuments()));
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
