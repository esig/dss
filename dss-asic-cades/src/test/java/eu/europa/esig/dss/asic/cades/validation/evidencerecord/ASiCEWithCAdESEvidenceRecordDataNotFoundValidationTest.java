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
package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESEvidenceRecordDataNotFoundValidationTest extends AbstractASiCWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/er-multi-file-data-not-found.asice");
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertEquals(1, Utils.collectionSize(detachedEvidenceRecords));
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);

        int validRefsCounter = 0;
        int invalidRefsCounter = 0;
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(2, Utils.collectionSize(referenceValidationList));
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            if (referenceValidation.isIntact()) {
                assertTrue(referenceValidation.isFound());
                ++validRefsCounter;
            } else {
                assertFalse(referenceValidation.isFound());
                ++invalidRefsCounter;
            }
        }
        assertEquals(1, validRefsCounter);
        assertEquals(1, invalidRefsCounter);

        List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
        assertTrue(Utils.isCollectionNotEmpty(timestampedReferences));

        int tstCounter = 0;

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertNotNull(timestampToken.getTimeStampType());
            assertNotNull(timestampToken.getArchiveTimestampType());
            assertNotNull(timestampToken.getEvidenceRecordTimestampType());

            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());

            if (tstCounter > 0) {
                List<ReferenceValidation> tstReferenceValidationList = timestampToken.getReferenceValidations();
                assertTrue(Utils.isCollectionNotEmpty(tstReferenceValidationList));

                boolean archiveTstDigestFound = false;
                boolean archiveTstSequenceDigestFound = false;
                for (ReferenceValidation referenceValidation : tstReferenceValidationList) {
                    if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(referenceValidation.getType())) {
                        archiveTstDigestFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE.equals(referenceValidation.getType())) {
                        archiveTstSequenceDigestFound = true;
                    }
                    assertTrue(referenceValidation.isFound());
                    assertTrue(referenceValidation.isIntact());
                }

                assertEquals(EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP == timestampToken.getEvidenceRecordTimestampType(), archiveTstDigestFound);
                assertEquals(EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestampToken.getEvidenceRecordTimestampType(), archiveTstSequenceDigestFound);

            } else {
                assertEquals(EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP, timestampToken.getEvidenceRecordTimestampType());
            }

            ++tstCounter;
        }
    }


    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);

        int validRefsCounter = 0;
        int invalidRefsCounter = 0;
        List<XmlDigestMatcher> digestMatcherList = evidenceRecord.getDigestMatchers();
        assertEquals(2, Utils.collectionSize(digestMatcherList));
        for (XmlDigestMatcher digestMatcher : digestMatcherList) {
            if (digestMatcher.isDataIntact()) {
                assertTrue(digestMatcher.isDataFound());
                ++validRefsCounter;
            } else {
                assertFalse(digestMatcher.isDataFound());
                ++invalidRefsCounter;
            }
        }
        assertEquals(1, validRefsCounter);
        assertEquals(1, invalidRefsCounter);
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        assertNotNull(simpleReport);

        for (String erId : simpleReport.getEvidenceRecordIdList()) {
            XmlEvidenceRecord xmlEvidenceRecord = simpleReport.getEvidenceRecordById(erId);
            assertNotNull(simpleReport.getEvidenceRecordPOE(erId));
            assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(erId));
            assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(erId));

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
            assertEquals(1, Utils.collectionSize(evidenceRecordScopes));

            XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
            assertNotNull(timestamps);
            assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

            for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
                assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

                List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
                assertEquals(1, Utils.collectionSize(timestampScopes));
            }
        }

        assertNotNull(simpleReport.getValidationTime());
    }

}
