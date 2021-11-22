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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDocumentReader;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeout;

public class PerformanceManySignaturesTest {

    @Test
    void extractSigDictionaries() throws IOException {
        InMemoryDocument inMemoryDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/51sigs.pdf"));

        PdfBoxDocumentReader reader = new PdfBoxDocumentReader(inMemoryDocument);
        Map<PdfSignatureDictionary, List<PdfSignatureField>> pdfSignatureDictionaryListMap = reader.extractSigDictionaries();
        assertNotNull(pdfSignatureDictionaryListMap);
    }

    @Test
    void getSignatures() {
        InMemoryDocument inMemoryDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/51sigs.pdf"));

        PDFDocumentValidator validator = new PDFDocumentValidator(inMemoryDocument);

        assertTimeout(Duration.ofSeconds(15), () -> validator.getRevisions());

        List<PdfRevision> revisions = assertTimeout(Duration.ofSeconds(1), () -> validator.getRevisions()); // cached
        assertNotNull(revisions);
        assertEquals(52, revisions.size());

        List<AdvancedSignature> signatures = assertTimeout(Duration.ofSeconds(2), () -> validator.getSignatures());
        assertNotNull(signatures);
        assertEquals(51, signatures.size());

        List<TimestampToken> detachedTimestamps = assertTimeout(Duration.ofSeconds(2), () -> validator.getDetachedTimestamps());
        assertNotNull(detachedTimestamps);
        assertEquals(0, detachedTimestamps.size());

        List<PdfDssDict> dssDictionaries = assertTimeout(Duration.ofSeconds(2), () -> validator.getDssDictionaries());
        assertNotNull(dssDictionaries);
        assertEquals(1, dssDictionaries.size());
        PdfDssDict pdfDssDict = dssDictionaries.get(0);
        assertEquals(59, pdfDssDict.getCERTs().size());
        assertEquals(0, pdfDssDict.getCRLs().size());
        assertEquals(1, pdfDssDict.getOCSPs().size());
        assertEquals(51, pdfDssDict.getVRIs().size());
    }

    @Test
    void retrievePreviousPDFRevisionFirst() {
        String expectedSHA256 = "zr24pCby+v9AN0effpTLOahaEBsynz/Ap0EoARhvpsI=";
        InMemoryDocument inMemoryDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/51sigs.pdf"));
        ByteRange byteRange = new ByteRange(new int[]{0, 4883, 23829, 70196});
        InMemoryDocument previousRevision = PAdESUtils.retrievePreviousPDFRevision(inMemoryDocument, byteRange);
        assertEquals(expectedSHA256, previousRevision.getDigest(DigestAlgorithm.SHA256));
    }

    @Test
    void retrievePreviousPDFRevisionLast() {
        String expectedSHA256 = "kRdqr7p5115vX+2McvMb/f0X/Jah0qPzKFrYrlY4v8E=";
        InMemoryDocument inMemoryDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/51sigs.pdf"));
        ByteRange byteRange = new ByteRange(new int[]{0, 4533638, 4552584, 17463});
        InMemoryDocument previousRevision = PAdESUtils.retrievePreviousPDFRevision(inMemoryDocument, byteRange);
        assertEquals(expectedSHA256, previousRevision.getDigest(DigestAlgorithm.SHA256));
    }

}
