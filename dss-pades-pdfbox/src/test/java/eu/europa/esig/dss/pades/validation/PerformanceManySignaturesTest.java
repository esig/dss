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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.pdf.PdfDocDssRevision;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDocumentReader;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PerformanceManySignaturesTest {

    @Test
    void extractSigDictionaries() throws IOException {
        InMemoryDocument inMemoryDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/51sigs.pdf"));

        try (PdfBoxDocumentReader reader = new PdfBoxDocumentReader(inMemoryDocument)) {
            Map<PdfSignatureDictionary, List<PdfSignatureField>> pdfSignatureDictionaryListMap = reader.extractSigDictionaries();
            assertNotNull(pdfSignatureDictionaryListMap);
        }
    }

    @Test
    void getSignatures() {
        InMemoryDocument inMemoryDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/51sigs.pdf"));
        initClasses(inMemoryDocument);

        PDFDocumentValidator validator = new PDFDocumentValidator(inMemoryDocument);

        assertTimeout(Duration.ofSeconds(3), () -> validator.getRevisions());

        List<PdfRevision> revisions = assertTimeout(Duration.ofSeconds(1), () -> validator.getRevisions()); // cached
        assertNotNull(revisions);
        assertEquals(52, revisions.size());

        List<AdvancedSignature> signatures = assertTimeout(Duration.ofSeconds(2), () -> validator.getSignatures());
        assertNotNull(signatures);
        assertEquals(51, signatures.size());

        List<EncapsulatedRevocationTokenIdentifier<?>> revocationBinaries = new ArrayList<>();
        for (AdvancedSignature signature : signatures) {
            assertTrue(signature instanceof PAdESSignature);
            PAdESSignature padesSignature = (PAdESSignature) signature;
            verifyRevocationSource(revocationBinaries, padesSignature.getCRLSource());
            verifyRevocationSource(revocationBinaries, padesSignature.getOCSPSource());
        }

        for (PdfRevision revision : revisions) {
            if (revision instanceof PdfDocDssRevision) {
                verifyRevocationSource(revocationBinaries, ((PdfDocDssRevision) revision).getCRLSource());
                verifyRevocationSource(revocationBinaries, ((PdfDocDssRevision) revision).getOCSPSource());
            }
        }

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

    // This method is used to initialize all the required classes, to avoid delay during unit test with timeout
    private void initClasses(DSSDocument documentToValidate) {
        PDFDocumentValidator validator = new PDFDocumentValidator(documentToValidate);
        validator.getRevisions();
    }

    private <R extends Revocation> void verifyRevocationSource(List<EncapsulatedRevocationTokenIdentifier<?>> binaries,
                                                               OfflineRevocationSource<R> source) {
        Set<EncapsulatedRevocationTokenIdentifier<R>> allRevocationBinaries = source.getAllRevocationBinaries();
        for (EncapsulatedRevocationTokenIdentifier<R> identifier : allRevocationBinaries) {
            // ensure same binaries == same object
            assertEquals(binaries.contains(identifier), containsMemoryObject(binaries, identifier));
        }
        binaries.addAll(allRevocationBinaries);
    }

    private <T> boolean containsMemoryObject(List<T> list, T object) {
        for (T item : list) {
            if (item == object) {
                return true;
            }
        }
        return false;
    }

}
