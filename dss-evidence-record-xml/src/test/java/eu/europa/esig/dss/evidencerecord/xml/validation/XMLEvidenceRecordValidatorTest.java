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
package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractTestEvidenceRecordValidator;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecordValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XMLEvidenceRecordValidatorTest extends AbstractTestEvidenceRecordValidator {

    @Test
    public void isSupported() {
        XMLEvidenceRecordValidator validator = new XMLEvidenceRecordValidator();

        byte[] wrongBytes = new byte[] { 1, 2 };
        assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes)));
        assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.PDF)));
        assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test")));
        assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.XML)));
        assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test.xml")));

        assertFalse(validator.isSupported(new InMemoryDocument(new byte[] { '<', '?', 'x', 'm', 'l' })));
        assertFalse(validator.isSupported(new InMemoryDocument(new byte[] { -17, -69, -65, '<' })));
        assertFalse(validator.isSupported(new InMemoryDocument(new byte[] { '<', 'd', 's', ':' })));
        assertFalse(validator.isSupported(new InMemoryDocument(new byte[] { '<', 'E', 'v', 'i', 'd', 'e', 'n', 'v', 'e' })));

        assertTrue(validator.isSupported(new FileDocument("src/test/resources/er-simple.xml")));
        assertTrue(validator.isSupported(new FileDocument("src/test/resources/er-perfect-tree.xml")));
        assertTrue(validator.isSupported(new FileDocument("src/test/resources/er-tst-renewal.xml")));
        assertTrue(validator.isSupported(new FileDocument("src/test/resources/er-chain-renewal.xml")));
        assertTrue(validator.isSupported(new FileDocument("src/test/resources/er-simple-bom.xml")));
    }

    @Override
    protected DefaultEvidenceRecordValidator initEmptyValidator() {
        return new XMLEvidenceRecordValidator();
    }

    @Override
    protected DefaultEvidenceRecordValidator initValidator(DSSDocument document) {
        return new XMLEvidenceRecordValidator(document);
    }

    @Override
    protected List<DSSDocument> getValidDocuments() {
        List<DSSDocument> documents = new ArrayList<>();
        documents.add(new FileDocument("src/test/resources/er-simple.xml"));
        documents.add(new FileDocument("src/test/resources/er-perfect-tree.xml"));
        documents.add(new FileDocument("src/test/resources/er-tst-renewal.xml"));
        documents.add(new FileDocument("src/test/resources/er-chain-renewal.xml"));
        documents.add(new FileDocument("src/test/resources/er-simple-bom.xml"));
        return documents;
    }

    @Override
    protected DSSDocument getMalformedDocument() {
        return new FileDocument("src/test/resources/er-malformed.xml");
    }

    @Override
    protected DSSDocument getOtherTypeDocument() {
        return new FileDocument("src/test/resources/Signature-C-LT.p7m");
    }

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/valid-xades.xml");
    }

}
