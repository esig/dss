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
package eu.europa.esig.dss.pades.timestamp.suite;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBTest;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PAdESServiceTimestampingTest extends AbstractPkiFactoryTestValidation {

    private static PAdESService service;

    @BeforeEach
    void init() {
        service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Test
    void nullTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> service.timestamp(null, null));
        assertEquals("Document to be timestamped is not defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> service.timestamp(InMemoryDocument.createEmptyDocument(), null));
        assertEquals("PAdESTimestampParameters cannot be null!", exception.getMessage());
    }

    @Test
    void digestDocumentTest() {
        DSSDocument originalDocument = new InMemoryDocument(PAdESLevelBTest.class.getResourceAsStream("/sample.pdf"));
        DSSDocument documentToTimestamp = new DigestDocument(DigestAlgorithm.SHA256, originalDocument.getDigestValue(DigestAlgorithm.SHA256));

        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                service.timestamp(documentToTimestamp, new PAdESTimestampParameters()));
        assertEquals("DigestDocument cannot be used! PDF document is expected!", exception.getMessage());
    }

    @Test
    void nonPdfTest() {
        DSSDocument documentToTimestamp = new InMemoryDocument(PAdESLevelBTest.class.getResourceAsStream("/signature-image.png"));

        Exception exception = assertThrows(IllegalInputException.class, () ->
                service.timestamp(documentToTimestamp, new PAdESTimestampParameters()));
        assertEquals("The document with name 'null' is not a PDF. PDF document is expected!", exception.getMessage());
    }

    @Override
    protected String getSigningAlias() {
        return null;
    }

}
