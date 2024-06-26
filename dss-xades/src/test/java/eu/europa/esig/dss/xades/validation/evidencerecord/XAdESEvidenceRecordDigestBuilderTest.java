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
package eu.europa.esig.dss.xades.validation.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.evidencerecord.XAdESEvidenceRecordDigestBuilder;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESEvidenceRecordDigestBuilderTest {

    @Test
    public void xadesNoErTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/X-B-B-basic.xml");

        assertEquals("E69F1ED3CE0AB6F8A72D9773CD9E862ED56E5C558DD79C2E695993810BC5B0E1",
                new XAdESEvidenceRecordDigestBuilder(document).build().getHexValue());
        assertEquals("C8DF45D3C0DB7694B27BC03BEED30B6C412A48CC",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA1).build().getHexValue());
        assertEquals("2FEBFCA97E70E18F56365123E279DA441598DE60E8B7F182473F65A6",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA224).build().getHexValue());
        assertEquals("E69F1ED3CE0AB6F8A72D9773CD9E862ED56E5C558DD79C2E695993810BC5B0E1",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("97520DEDC00AF6A85AE7CB74D4134D59C5D3D322D49A077573BFD3BC784E0B35B24BDF250EE5B406845D03C703BF885F2B1BFC88C7767C91B1301F4153C01BD6",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512).build().getHexValue());
        assertEquals("E69F1ED3CE0AB6F8A72D9773CD9E862ED56E5C558DD79C2E695993810BC5B0E1",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals("E69F1ED3CE0AB6F8A72D9773CD9E862ED56E5C558DD79C2E695993810BC5B0E1",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    public void xadesWithErTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-basic.xml");

        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId("invalid-sig-id").build());
        assertEquals("No signature with Id 'invalid-sig-id' found in the document!", exception.getMessage());

        String sigId = "id-b922f76108a1fe54051e562afb8678b9";

        assertEquals("28FAD563B04EE8485EFFA92FFB1B52CAC15C63FAA87737E5C4D069874A8AFA5F",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("28FAD563B04EE8485EFFA92FFB1B52CAC15C63FAA87737E5C4D069874A8AFA5F",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId(sigId).build().getHexValue());
        assertEquals("28FAD563B04EE8485EFFA92FFB1B52CAC15C63FAA87737E5C4D069874A8AFA5F",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals("E69F1ED3CE0AB6F8A72D9773CD9E862ED56E5C558DD79C2E695993810BC5B0E1",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    public void xadesLtWithErTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-LT.xml");

        Exception exception = assertThrows(IllegalInputException.class, () ->
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).build());
        assertEquals("The provided document contains multiple signatures! " +
                "Please use #setSignatureId method in order to provide the identifier.", exception.getMessage());

        String sigId = "id-270f7c0b892f5ad2a1178a20b68d101a";

        assertEquals("C5440F1277B56A4854E1ABE5184DFE89B2B055B09DDCE89C07D5ECA2685CFA34",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId(sigId).build().getHexValue());
        assertEquals("C5440F1277B56A4854E1ABE5184DFE89B2B055B09DDCE89C07D5ECA2685CFA34",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId(sigId).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals("419D553E1CAF588435C616029FF19B0E1CCBB4D4A6FACD89B9FB93A9DA2A98F8",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId(sigId).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    public void xadesLtDetachedWithErTest() {
        DSSDocument signatureDoc = new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-DETACHED-LT.xml");
        DSSDocument detachedDoc = new FileDocument("src/test/resources/sample.xml");

        Exception exception = assertThrows(DSSException.class, () -> new XAdESEvidenceRecordDigestBuilder(signatureDoc, DigestAlgorithm.SHA256).build());
        assertTrue(exception.getMessage().contains("An error occurred on ds:Reference processing. " +
                        "In case of detached signature, please use #setDetachedContent method to provide original documents."));

        assertEquals("40C9BAD41AE78248C4EABDDFBECAD28D7A505EF14382F856379CF9B19DD78908",
                new XAdESEvidenceRecordDigestBuilder(signatureDoc, DigestAlgorithm.SHA256)
                        .setDetachedContent(Collections.singletonList(detachedDoc)).build().getHexValue());
        assertEquals("40C9BAD41AE78248C4EABDDFBECAD28D7A505EF14382F856379CF9B19DD78908",
                new XAdESEvidenceRecordDigestBuilder(signatureDoc, DigestAlgorithm.SHA256)
                        .setDetachedContent(Collections.singletonList(detachedDoc)).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals("8EBBC33629E40276970F8F4E135D7B4C77BB28F6A695CB522AF8AB003ADF4B88",
                new XAdESEvidenceRecordDigestBuilder(signatureDoc, DigestAlgorithm.SHA256)
                        .setDetachedContent(Collections.singletonList(detachedDoc)).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    public void xadesManifestWithErTest() {
        DSSDocument signatureDoc = new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-MANIFEST.xml");

        List<DSSDocument> detachedDocuments = new ArrayList<>();
        detachedDocuments.add(new FileDocument("src/test/resources/sample.png"));
        detachedDocuments.add(new FileDocument("src/test/resources/sample.txt"));
        detachedDocuments.add(new FileDocument("src/test/resources/sample.xml"));

        assertEquals("03898DAD5D4015A33610C00045277D36AC8E0ABC3487DC9ED674978B9C44D8E2",
                new XAdESEvidenceRecordDigestBuilder(signatureDoc, DigestAlgorithm.SHA256)
                        .setDetachedContent(detachedDocuments).build().getHexValue());
        assertEquals("03898DAD5D4015A33610C00045277D36AC8E0ABC3487DC9ED674978B9C44D8E2",
                new XAdESEvidenceRecordDigestBuilder(signatureDoc, DigestAlgorithm.SHA256)
                        .setDetachedContent(detachedDocuments).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals("FBBDB34A1C6FB63B89275BDCB7CA05E73EEFC071010567C3E443033925EE1734",
                new XAdESEvidenceRecordDigestBuilder(signatureDoc, DigestAlgorithm.SHA256)
                        .setDetachedContent(detachedDocuments).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    public void twoSigsLtWithErTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/Double-sig-X-E-ERS-LT.xml");

        Exception exception = assertThrows(IllegalInputException.class, () ->
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).build());
        assertEquals("The provided document contains multiple signatures! " +
                "Please use #setSignatureId method in order to provide the identifier.", exception.getMessage());

        String sigId = "id-270f7c0b892f5ad2a1178a20b68d101a";

        assertEquals("C5440F1277B56A4854E1ABE5184DFE89B2B055B09DDCE89C07D5ECA2685CFA34",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId(sigId).build().getHexValue());
        assertEquals("C5440F1277B56A4854E1ABE5184DFE89B2B055B09DDCE89C07D5ECA2685CFA34",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId(sigId).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals("419D553E1CAF588435C616029FF19B0E1CCBB4D4A6FACD89B9FB93A9DA2A98F8",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId(sigId).setParallelEvidenceRecord(true).build().getHexValue());

        sigId = "id-6af532b50e9d95dfe0118830e0c0a6fe";

        assertEquals("194D678EC430FA7E12C778E5C97FB03AF60339D0BFDB6EC4D5E7299FD4FE40C8",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId(sigId).build().getHexValue());
        assertEquals("194D678EC430FA7E12C778E5C97FB03AF60339D0BFDB6EC4D5E7299FD4FE40C8",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId(sigId).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals("FD1833DC3695ECCB5716C68CC7618B043F73DC4A1CEE5F2C63E2ECDD6C00F2DC",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setSignatureId(sigId).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    public void xadesLtWithTwoErsTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-two-ers.xml");

        assertEquals("461D84AEDC1FE1D957FFA4F00E12463C49C8752C3EB242CC7A16EAEC94F6D6AC",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("461D84AEDC1FE1D957FFA4F00E12463C49C8752C3EB242CC7A16EAEC94F6D6AC",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals("28FAD563B04EE8485EFFA92FFB1B52CAC15C63FAA87737E5C4D069874A8AFA5F",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    public void xadesLtWithTwoParallelErsTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-two-parallel-ers.xml");

        assertEquals("DDC64E2A03C392C1C7C11932461FB4757CBB0E932111722ECEB16CF8147E8C09",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("DDC64E2A03C392C1C7C11932461FB4757CBB0E932111722ECEB16CF8147E8C09",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals("E69F1ED3CE0AB6F8A72D9773CD9E862ED56E5C558DD79C2E695993810BC5B0E1",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());
    }

    @Test
    public void xadesWithAsn1ErTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-basic-asn1.xml");

        assertEquals("071839D59D47CB24483DC87752DD3B235F2CB50C2CB537ED88DFC7D491A15B8C",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("071839D59D47CB24483DC87752DD3B235F2CB50C2CB537ED88DFC7D491A15B8C",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setParallelEvidenceRecord(false).build().getHexValue());
        assertEquals("E69F1ED3CE0AB6F8A72D9773CD9E862ED56E5C558DD79C2E695993810BC5B0E1",
                new XAdESEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA256).setParallelEvidenceRecord(true).build().getHexValue());
    }
    
}
