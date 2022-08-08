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
package eu.europa.esig.dss.asic.xades.extension.asics;

import eu.europa.esig.dss.asic.common.ContainerEntryDocument;
import eu.europa.esig.dss.asic.common.DSSZipEntry;
import eu.europa.esig.dss.asic.common.DSSZipEntryDocument;
import eu.europa.esig.dss.asic.common.SecureContainerHandler;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.asics.AbstractASiCSWithXAdESMultipleDocumentsTestSignature;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ASiCsExtensionWithXAdESBToLTAWithZipEntryDocTest extends AbstractASiCSWithXAdESMultipleDocumentsTestSignature {

    private ContainerEntryDocument documentOne;
    private ContainerEntryDocument documentTwo;

    private ASiCWithXAdESService service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentToSigns = new ArrayList<>();

    @BeforeEach
    public void init() throws Exception {
        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        DSSZipEntry zipEntryOne = new DSSZipEntry("docOne.txt");
        zipEntryOne.setComment("Nowina Solutions document");

        documentOne = new ContainerEntryDocument(
                new InMemoryDocument("Hello World !".getBytes(), zipEntryOne.getName()), zipEntryOne);

        documentToSigns.add(documentOne);

        DSSZipEntry zipEntryTwo = new DSSZipEntry("docTwo.txt");
        zipEntryTwo.setCompressionMethod(ZipEntry.STORED);
        zipEntryTwo.setCreationTime(DSSUtils.getUtcDate(2020, 0, 1));

        documentTwo = new ContainerEntryDocument(
                new InMemoryDocument("Bye World !".getBytes(), zipEntryTwo.getName()), zipEntryTwo);

        documentToSigns.add(documentTwo);

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
        secureContainerHandler.setExtractComments(true);
        ZipUtils.getInstance().setZipContainerHandler(secureContainerHandler);
    }

    @AfterAll
    public static void reset() {
        ZipUtils.getInstance().setZipContainerHandler(new SecureContainerHandler());
    }

    @Override
    protected DSSDocument sign() {
        try {
            DSSDocument signedDocument = super.sign();

            File file = new File("target/" + signedDocument.getName());
            signedDocument.save(file.getPath());
            assertTrue(file.exists());

            DSSDocument tempDocument = new FileDocument(file);
            verifyMetadata(tempDocument);

            signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
            DSSDocument extendedDocument = service.extendDocument(tempDocument, signatureParameters);

            extendedDocument.save(file.getPath());

            tempDocument = new FileDocument(file);
            verifyMetadata(tempDocument);

            assertTrue(file.delete());
            assertFalse(file.exists());

            return extendedDocument;

        } catch (IOException e) {
            fail(e);
            return null;
        }
    }

    private void verifyMetadata(DSSDocument archive) throws IOException {
        List<DSSDocument> dssDocuments = ZipUtils.getInstance().extractContainerContent(archive);

        boolean firstDocFound = false;
        boolean secondDocFound = false;

        for (DSSDocument document : dssDocuments) {
            assertTrue(document instanceof DSSZipEntryDocument);
            DSSZipEntryDocument dssZipEntry = (DSSZipEntryDocument) document;
            DSSZipEntry entry = dssZipEntry.getZipEntry();

            if ("package.zip".equals(entry.getName())) {
                assertEquals(ZipEntry.DEFLATED, entry.getCompressionMethod());

                File file = new File("target/" + document.getName());
                document.save(file.getPath());
                assertTrue(file.exists());

                DSSDocument tempDocument = new FileDocument(file);
                List<DSSDocument> originalDocs = ZipUtils.getInstance().extractContainerContent(tempDocument);

                for (DSSDocument originalDoc : originalDocs) {
                    assertTrue(originalDoc instanceof DSSZipEntryDocument);
                    dssZipEntry = (DSSZipEntryDocument) originalDoc;
                    entry = dssZipEntry.getZipEntry();

                    if (documentOne.getName().equals(entry.getName())) {
                        assertEquals(documentOne.getZipEntry().getComment(), entry.getComment());
                        assertEquals(documentOne.getZipEntry().getCompressionMethod(), entry.getCompressionMethod());
                        assertNull(entry.getCreationTime());
                        firstDocFound = true;

                    } else if (documentTwo.getName().equals(entry.getName())) {
                        assertNull(entry.getComment());
                        assertEquals(documentTwo.getZipEntry().getCompressionMethod(), entry.getCompressionMethod());
                        assertEquals(documentTwo.getZipEntry().getCreationTime(), entry.getCreationTime());
                        secondDocFound = true;
                    }
                }

                assertTrue(file.delete());
                assertFalse(file.exists());
            }
        }
        assertTrue(firstDocFound);
        assertTrue(secondDocFound);
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
