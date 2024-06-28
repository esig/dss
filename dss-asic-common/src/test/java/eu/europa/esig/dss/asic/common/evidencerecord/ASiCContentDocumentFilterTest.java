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
package eu.europa.esig.dss.asic.common.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ASiCContentDocumentFilterTest {

    @Test
    void test() {
        DSSDocument documentOne = new InMemoryDocument("Hello World".getBytes(), "hello.txt");
        DSSDocument documentTwo = new InMemoryDocument("Bye World".getBytes(), "bye.txt");

        ASiCContent asicContent = new ASiCContent();
        asicContent.setSignedDocuments(Arrays.asList(documentOne, documentTwo));

        ASiCContentDocumentFilter asicContentDocumentFilter = new ASiCContentDocumentFilter();
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setSignedDocuments(true);
        assertEquals(Arrays.asList(documentOne, documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(Collections.singleton("hello.txt"));
        assertEquals(Collections.singletonList(documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(null);
        asicContentDocumentFilter.setSignedDocuments(false);
        asicContentDocumentFilter.setSignatureDocuments(true);
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContent.setSignedDocuments(null);
        asicContent.setSignatureDocuments(Arrays.asList(documentOne, documentTwo));
        assertEquals(Arrays.asList(documentOne, documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(Collections.singleton("bye.txt"));
        assertEquals(Collections.singletonList(documentOne), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(null);
        asicContentDocumentFilter.setSignatureDocuments(false);
        asicContentDocumentFilter.setTimestampDocuments(true);
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContent.setSignatureDocuments(null);
        asicContent.setTimestampDocuments(Arrays.asList(documentOne, documentTwo));
        assertEquals(Arrays.asList(documentOne, documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(Collections.emptyList());
        assertEquals(Arrays.asList(documentOne, documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(null);
        asicContentDocumentFilter.setTimestampDocuments(false);
        asicContentDocumentFilter.setEvidenceRecordDocuments(true);
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContent.setSignatureDocuments(null);
        asicContent.setEvidenceRecordDocuments(Arrays.asList(documentOne, documentTwo));
        assertEquals(Arrays.asList(documentOne, documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(Arrays.asList("hello.txt", "bye.txt"));
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(null);
        asicContentDocumentFilter.setEvidenceRecordDocuments(false);
        asicContentDocumentFilter.setManifestDocuments(true);
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContent.setEvidenceRecordDocuments(null);
        asicContent.setManifestDocuments(Arrays.asList(documentOne, documentTwo));
        assertEquals(Arrays.asList(documentOne, documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(Collections.singleton("hello.txt"));
        assertEquals(Collections.singletonList(documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(null);
        asicContentDocumentFilter.setManifestDocuments(false);
        asicContentDocumentFilter.setArchiveManifestDocuments(true);
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContent.setManifestDocuments(null);
        asicContent.setArchiveManifestDocuments(Arrays.asList(documentOne, documentTwo));
        assertEquals(Arrays.asList(documentOne, documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(Collections.singleton("hello.txt"));
        assertEquals(Collections.singletonList(documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(null);
        asicContentDocumentFilter.setArchiveManifestDocuments(false);
        asicContentDocumentFilter.setEvidenceRecordManifestDocuments(true);
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContent.setArchiveManifestDocuments(null);
        asicContent.setEvidenceRecordManifestDocuments(Arrays.asList(documentOne, documentTwo));
        assertEquals(Arrays.asList(documentOne, documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(Collections.singleton("hello.txt"));
        assertEquals(Collections.singletonList(documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(null);
        asicContentDocumentFilter.setEvidenceRecordManifestDocuments(false);
        asicContentDocumentFilter.setUnsupportedDocuments(true);
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContent.setEvidenceRecordManifestDocuments(null);
        asicContent.setUnsupportedDocuments(Arrays.asList(documentOne, documentTwo));
        assertEquals(Arrays.asList(documentOne, documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(Collections.singleton("hello.txt"));
        assertEquals(Collections.singletonList(documentTwo), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(null);
        asicContentDocumentFilter.setUnsupportedDocuments(false);
        asicContentDocumentFilter.setMimetypeDocument(true);
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));

        asicContent.setUnsupportedDocuments(null);
        asicContent.setMimeTypeDocument(documentOne);
        assertEquals(Collections.singletonList(documentOne), asicContentDocumentFilter.filter(asicContent));

        asicContentDocumentFilter.setExcludedFilenames(Collections.singleton("hello.txt"));
        assertEquals(Collections.emptyList(), asicContentDocumentFilter.filter(asicContent));
    }

}
