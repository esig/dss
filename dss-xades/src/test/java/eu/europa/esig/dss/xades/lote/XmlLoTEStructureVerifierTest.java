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
package eu.europa.esig.dss.xades.lote;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlLoTEStructureVerifierTest {

    @Test
    void validNoSigTest() {
        DSSDocument loteDocument = new FileDocument("src/test/resources/lote/lote-valid.xml");

        XmlLoTEStructureVerifier verifier = new XmlLoTEStructureVerifier();

        verifier.setSigningMode(true);
        List<String> errors = verifier.validate(loteDocument);
        assertTrue(Utils.isCollectionEmpty(errors), errors.toString());

        verifier.setSigningMode(false);
        errors = verifier.validate(loteDocument);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("No ds:Signature element is present!")), errors.toString());
    }

    @Test
    void invalidNoSigTest() {
        DSSDocument loteDocument = new FileDocument("src/test/resources/lote/lote-invalid.xml");

        XmlLoTEStructureVerifier verifier = new XmlLoTEStructureVerifier();

        verifier.setSigningMode(true);
        List<String> errors = verifier.validate(loteDocument);
        assertFalse(Utils.isCollectionEmpty(errors), errors.toString());
        assertTrue(errors.stream().anyMatch(r -> r.contains("ListAndSchemeInformation")), errors.toString());

        verifier.setSigningMode(false);
        errors = verifier.validate(loteDocument);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("No ds:Signature element is present!")), errors.toString());
    }

    @Test
    void validSignedTest() {
        DSSDocument loteDocument = new FileDocument("src/test/resources/lote/lote-valid-signed.xml");

        XmlLoTEStructureVerifier verifier = new XmlLoTEStructureVerifier();

        verifier.setSigningMode(true);
        List<String> errors = verifier.validate(loteDocument);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The ds:Signature element shall not be present for XML List of Trusted Entities signing!")), errors.toString());

        verifier.setSigningMode(false);
        errors = verifier.validate(loteDocument);
        assertTrue(Utils.isCollectionEmpty(errors));
    }

    @Test
    void nonLoTETest() {
        DSSDocument document = new FileDocument("src/test/resources/sample.xml");

        XmlLoTEStructureVerifier verifier = new XmlLoTEStructureVerifier();

        verifier.setSigningMode(true);
        List<String> errors = verifier.validate(document);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The root of XML List of Trusted Entities shall be lote:ListOfTrustedEntities element!")), errors.toString());

        verifier.setSigningMode(false);
        errors = verifier.validate(document);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The root of XML List of Trusted Entities shall be lote:ListOfTrustedEntities element!")), errors.toString());
    }

    @Test
    void nonXmlTest() {
        DSSDocument document = new FileDocument("src/test/resources/sample.txt");

        XmlLoTEStructureVerifier verifier = new XmlLoTEStructureVerifier();

        verifier.setSigningMode(true);
        List<String> errors = verifier.validate(document);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The document is not a valid XML document!")), errors.toString());

        verifier.setSigningMode(false);
        errors = verifier.validate(document);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The document is not a valid XML document!")), errors.toString());
    }

    @Test
    void nullTest() {
        XmlLoTEStructureVerifier verifier = new XmlLoTEStructureVerifier();

        Exception exception = assertThrows(NullPointerException.class, () -> verifier.validate((DSSDocument) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> verifier.validate((Document) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());

        verifier.setSigningMode(true);

        exception = assertThrows(NullPointerException.class, () -> verifier.validate((DSSDocument) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> verifier.validate((Document) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());

        verifier.setSigningMode(false);

        exception = assertThrows(NullPointerException.class, () -> verifier.validate((DSSDocument) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> verifier.validate((Document) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());
    }

}
