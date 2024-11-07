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
package eu.europa.esig.dss.pdf.openpdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import org.junit.jupiter.api.Test;

import com.lowagie.text.pdf.PdfObject;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.test.PKIFactoryAccess;

class ITextDocumentReaderTest extends PKIFactoryAccess {

    @Test
    void permissionsSimpleDocument() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        try (ITextDocumentReader documentReader = new ITextDocumentReader(dssDocument)) {
            assertFalse(documentReader.isEncrypted());
            assertTrue(documentReader.isOpenWithOwnerAccess());
            assertTrue(documentReader.canFillSignatureForm());
            assertTrue(documentReader.canCreateSignatureField());
        }
    }

    @Test
    void permissionsProtectedDocument() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/open_protected.pdf"));
		try (ITextDocumentReader documentReader = new ITextDocumentReader(dssDocument, new byte[] { ' ' })) {
            assertTrue(documentReader.isEncrypted());
            assertTrue(documentReader.isOpenWithOwnerAccess());
            assertTrue(documentReader.canFillSignatureForm());
            assertTrue(documentReader.canCreateSignatureField());
        }
    }

    @Test
    void permissionsEditionProtectedDocument() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/edition_protected_none.pdf"));
        try (ITextDocumentReader documentReader = new ITextDocumentReader(dssDocument, new byte[]{ ' ' })) {
            assertTrue(documentReader.isEncrypted());
            assertTrue(documentReader.isOpenWithOwnerAccess());
            assertTrue(documentReader.canFillSignatureForm());
            assertTrue(documentReader.canCreateSignatureField());
        }
    }

    @Test
    void permissionsEditionNoFieldsProtectedDocument() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/edition_protected_signing_allowed_no_field.pdf"));
        try (ITextDocumentReader documentReader = new ITextDocumentReader(dssDocument, new byte[]{ ' ' })) {
            assertTrue(documentReader.isEncrypted());
            assertTrue(documentReader.isOpenWithOwnerAccess());
            assertTrue(documentReader.canFillSignatureForm());
            assertTrue(documentReader.canCreateSignatureField());
        }
    }

    @Test
    void generateDocumentIdTest() throws IOException {
        DSSDocument firstDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        DSSDocument secondDocument = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

        Date date = new Date();
        PAdESSignatureParameters parametersOne = new PAdESSignatureParameters();
        parametersOne.bLevel().setSigningDate(date);
        PAdESSignatureParameters parametersTwo = new PAdESSignatureParameters();
        parametersTwo.bLevel().setSigningDate(date);

        try (ITextDocumentReader firstReader = new ITextDocumentReader(firstDocument);
             ITextDocumentReader secondReader = new ITextDocumentReader(secondDocument)) {
            assertEquals(firstReader.generateDocumentId(parametersOne).toString(), firstReader.generateDocumentId(parametersOne).toString());
            assertEquals(firstReader.generateDocumentId(parametersTwo).toString(), firstReader.generateDocumentId(parametersTwo).toString());
            assertEquals(secondReader.generateDocumentId(parametersOne).toString(), secondReader.generateDocumentId(parametersOne).toString());
            assertEquals(secondReader.generateDocumentId(parametersTwo).toString(), secondReader.generateDocumentId(parametersTwo).toString());

            assertEquals(firstReader.generateDocumentId(parametersOne).toString(), firstReader.generateDocumentId(parametersTwo).toString());
            assertEquals(secondReader.generateDocumentId(parametersOne).toString(), secondReader.generateDocumentId(parametersTwo).toString());

            assertNotEquals(firstReader.generateDocumentId(parametersOne).toString(), secondReader.generateDocumentId(parametersOne).toString());
            assertNotEquals(firstReader.generateDocumentId(parametersTwo).toString(), secondReader.generateDocumentId(parametersTwo).toString());

            PdfObject docIdOne = firstReader.generateDocumentId(parametersOne);
            firstDocument.setName("newDocName");
            assertNotEquals(docIdOne.toString(), firstReader.generateDocumentId(parametersOne).toString());

            secondDocument.setName("newDocName");
            assertNotEquals(firstReader.generateDocumentId(parametersOne).toString(), secondReader.generateDocumentId(parametersOne).toString());

            parametersTwo.setSigningCertificate(getCertificate(GOOD_USER));
            parametersTwo.reinit();
            assertEquals(firstReader.generateDocumentId(parametersTwo).toString(), firstReader.generateDocumentId(parametersTwo).toString());
            assertNotEquals(firstReader.generateDocumentId(parametersOne).toString(), firstReader.generateDocumentId(parametersTwo).toString());

            parametersOne.setSigningCertificate(getCertificate(RSA_SHA3_USER));
            parametersOne.reinit();
            assertEquals(firstReader.generateDocumentId(parametersOne).toString(), firstReader.generateDocumentId(parametersOne).toString());
            assertNotEquals(firstReader.generateDocumentId(parametersOne).toString(), firstReader.generateDocumentId(parametersTwo).toString());

            // time test
            for (int i = 0; i < 1000; i++) {
                PAdESSignatureParameters sameTimeParameters = new PAdESSignatureParameters();
                sameTimeParameters.bLevel().setSigningDate(date);

                PAdESSignatureParameters diffTimeParameters = new PAdESSignatureParameters();
                Calendar calendar = Calendar.getInstance();
                calendar.setTime(new Date());
                calendar.add(Calendar.MILLISECOND, 1);
                diffTimeParameters.bLevel().setSigningDate(calendar.getTime());
                assertNotEquals(firstReader.generateDocumentId(sameTimeParameters).toString(),
                        firstReader.generateDocumentId(diffTimeParameters).toString());
                assertEquals(firstReader.generateDocumentId(diffTimeParameters).toString(),
                        firstReader.generateDocumentId(diffTimeParameters).toString());
            }
        }
    }

    @Test
    void fileHeaderVersionTest() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        assertEquals(1.4f, new ITextDocumentReader(dssDocument).getPdfHeaderVersion());
        dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/testdoc.pdf"));
        assertEquals(1.7f, new ITextDocumentReader(dssDocument).getPdfHeaderVersion());
        dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/pdf-2.0.pdf"));
        assertEquals(2.0f, new ITextDocumentReader(dssDocument).getPdfHeaderVersion());
        dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/muestra-firmado-firmado.pdf"));
        assertEquals(1.4f, new ITextDocumentReader(dssDocument).getPdfHeaderVersion());
    }

    @Test
    void versionTest() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        assertEquals(1.4f, new ITextDocumentReader(dssDocument).getVersion());
        dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/testdoc.pdf"));
        assertEquals(1.7f, new ITextDocumentReader(dssDocument).getVersion());
        dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/pdf-2.0.pdf"));
        assertEquals(2.0f, new ITextDocumentReader(dssDocument).getVersion());
        dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/muestra-firmado-firmado.pdf"));
        assertEquals(2.0f, new ITextDocumentReader(dssDocument).getVersion());
    }

    @Test
    void setVersionTest() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        ITextDocumentReader documentReader = new ITextDocumentReader(dssDocument);
        assertEquals(1.4f, documentReader.getVersion());

        documentReader.setVersion(1.7f);
        assertEquals(1.7f, documentReader.getVersion());

        documentReader.setVersion(2.0f);
        assertEquals(2.0f, documentReader.getVersion());
    }

    @Override
    protected String getSigningAlias() {
        return null;
    }

}
