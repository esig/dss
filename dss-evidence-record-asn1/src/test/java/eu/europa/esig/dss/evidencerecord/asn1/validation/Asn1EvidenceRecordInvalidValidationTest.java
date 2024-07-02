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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Asn1EvidenceRecordInvalidValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-asn1-simple-invalid.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(
                new DigestDocument(DigestAlgorithm.SHA256, "nOPX01D5QYQHQ58MoR3MEquffNsV+ezF7Kk1SCYCuHI=", "doc1"),
                new DigestDocument(DigestAlgorithm.SHA256, "7s1NM1LA6WX9iHle39GmDFrAmzwRAMBS67auC9NDKyY=", "doc2")
        );
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);

        List<ReferenceValidation> referenceValidations = evidenceRecord.getReferenceValidation();
        assertEquals(2, referenceValidations.size());
        for (ReferenceValidation referenceValidation : referenceValidations) {
            assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, referenceValidation.getType());
            assertNotNull(referenceValidation.getDocumentName());
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        assertEquals(1, Utils.collectionSize(evidenceRecord.getTimestamps()));
        TimestampToken timestampToken = evidenceRecord.getTimestamps().get(0);
        assertTrue(timestampToken.isMessageImprintDataFound());
        assertFalse(timestampToken.isMessageImprintDataIntact());
        List<ReferenceValidation> refValidations = timestampToken.getReferenceValidations();
        assertEquals(0, refValidations.size());
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

}
