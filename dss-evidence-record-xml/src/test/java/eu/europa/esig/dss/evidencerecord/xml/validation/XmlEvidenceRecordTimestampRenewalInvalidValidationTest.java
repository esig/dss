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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlEvidenceRecordTimestampRenewalInvalidValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-tst-renewal-invalid.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "Y0sCextp4SQtQNU+MSs7SsdxD1W+gfKJtUlEbvZ3i+4="));
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertEquals(1, detachedEvidenceRecords.size());

        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(1, referenceValidationList.size());

        ReferenceValidation referenceValidation = referenceValidationList.get(0);
        assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, referenceValidation.getType());
        assertTrue(referenceValidation.isFound());
        assertTrue(referenceValidation.isIntact());

        int passedTstCounter = 0;
        int failedTstCounter = 0;

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        assertEquals(3, timestamps.size());

        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());

            List<ReferenceValidation> tstReferenceValidationList = timestampToken.getReferenceValidations();
            if (Utils.isCollectionNotEmpty(tstReferenceValidationList)) {
                for (ReferenceValidation tstReferenceValidation : tstReferenceValidationList) {
                    assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP, tstReferenceValidation.getType());
                    assertTrue(tstReferenceValidation.isFound());
                    assertFalse(tstReferenceValidation.isIntact());
                }
                ++failedTstCounter;

            } else {
                ++passedTstCounter;
            }
        }

        assertEquals(1, passedTstCounter);
        assertEquals(2, failedTstCounter);
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        int passedTstCounter = 0;
        int failedTstCounter = 0;

        for (TimestampWrapper timestampWrapper : timestampList) {
            boolean failedDigestMatcherFound = false;
            boolean messageImprintDigestMatcherFound = false;
            for (XmlDigestMatcher digestMatcher : timestampWrapper.getDigestMatchers()) {
                if (DigestMatcherType.MESSAGE_IMPRINT.equals(digestMatcher.getType())) {
                    assertTrue(digestMatcher.isDataFound());
                    assertTrue(digestMatcher.isDataIntact());
                    messageImprintDigestMatcherFound = true;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(digestMatcher.getType())) {
                    failedDigestMatcherFound = true;
                    assertTrue(digestMatcher.isDataFound());
                    assertFalse(digestMatcher.isDataIntact());
                }
            }
            assertTrue(messageImprintDigestMatcherFound);

            if (failedDigestMatcherFound) {
                ++failedTstCounter;
            } else {
                ++passedTstCounter;
            }
        }

        assertEquals(1, passedTstCounter);
        assertEquals(2, failedTstCounter);
    }

}
