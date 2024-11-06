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
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ITextSignatureFieldTest extends PKIFactoryAccess {

    private PAdESService padesService = new PAdESService(new CommonCertificateVerifier());

    @Test
    void testGetSignatureFields() {
        assertTrue(Utils.isCollectionNotEmpty(padesService.getAvailableSignatureFields(
                new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf")))));
    }

    @Test
    void testAddSignatureField() {
        DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        assertTrue(Utils.isCollectionEmpty(padesService.getAvailableSignatureFields(document)));

        SignatureFieldParameters parameters = new SignatureFieldParameters();
        parameters.setPage(1);
        parameters.setFieldId("signature-test");
        parameters.setOriginX(50);
        parameters.setOriginY(50);
        parameters.setWidth(200);
        parameters.setHeight(200);

        DSSDocument newDocument = padesService.addNewSignatureField(document, parameters);

        List<String> availableSignatureFields = padesService.getAvailableSignatureFields(newDocument);
        assertTrue(availableSignatureFields.contains("signature-test"));

        parameters = new SignatureFieldParameters();
        parameters.setPage(1);
        parameters.setFieldId("signature-test2");
        parameters.setOriginX(300);
        parameters.setOriginY(50);
        parameters.setWidth(50);
        parameters.setHeight(50);

        DSSDocument newDocument2 = padesService.addNewSignatureField(newDocument, parameters);
        availableSignatureFields = padesService.getAvailableSignatureFields(newDocument2);
        assertEquals(2, availableSignatureFields.size());
    }

    @Test
    void testAddSignatureFieldPageNotFound() {
        DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        assertTrue(Utils.isCollectionEmpty(padesService.getAvailableSignatureFields(document)));

        SignatureFieldParameters parameters = new SignatureFieldParameters();
        parameters.setPage(10);
        parameters.setFieldId("signature-test");
        parameters.setOriginX(50);
        parameters.setOriginY(50);
        parameters.setWidth(200);
        parameters.setHeight(200);

        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> padesService.addNewSignatureField(document, parameters));
        assertEquals("The page number '10' does not exist in the file!", exception.getMessage());
    }

    @Test
    void addSignatureFieldToEncryptedPdfTest() {
        DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/pdf-with-annotations.pdf"));
        List<String> availableSignatureFields = padesService.getAvailableSignatureFields(document);
        assertFalse(Utils.isCollectionNotEmpty(availableSignatureFields));

        SignatureFieldParameters parameters = new SignatureFieldParameters();
        parameters.setFieldId("signature-test");

        DSSDocument docWithSignatureField = padesService.addNewSignatureField(document, parameters);
        availableSignatureFields = padesService.getAvailableSignatureFields(docWithSignatureField);
        assertTrue(Utils.isCollectionNotEmpty(availableSignatureFields));
        assertEquals("signature-test", availableSignatureFields.get(0));
    }

    @Test
    void signNonSignatureFieldTest() {
        DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

        PAdESSignatureParameters padesSignatureParameters = new PAdESSignatureParameters();
        padesSignatureParameters.setSigningCertificate(getSigningCert());
        padesSignatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        SignatureImageParameters signatureImageParameters = new SignatureImageParameters();

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setFieldId("First Name");

        signatureImageParameters.setFieldParameters(fieldParameters);
        padesSignatureParameters.setImageParameters(signatureImageParameters);

        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> padesService.getDataToSign(document, padesSignatureParameters));
        assertEquals("The signature field with id 'First Name' does not exist.", exception.getMessage());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}