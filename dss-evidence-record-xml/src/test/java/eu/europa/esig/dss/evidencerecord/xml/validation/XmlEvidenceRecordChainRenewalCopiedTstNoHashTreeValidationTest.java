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
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlEvidenceRecordChainRenewalCopiedTstNoHashTreeValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-chain-renewal-copied-tst-no-hashtree.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("da2e47f2-53f4-4610-8210-f0f05d67d0c9".getBytes()));
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertTrue(Utils.isCollectionNotEmpty(detachedEvidenceRecords));

        for (EvidenceRecord evidenceRecord : detachedEvidenceRecords) {
            List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
            for (ReferenceValidation referenceValidation : referenceValidationList) {
                if (allArchiveDataObjectsProvidedToValidation() ||
                        DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType()) {
                    assertTrue(referenceValidation.isFound());
                    assertTrue(referenceValidation.isIntact());
                }
            }

            List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
            assertTrue(Utils.isCollectionNotEmpty(timestampedReferences));

            List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
            assertEquals(3, timestamps.size());

            int validTstCounter = 0;
            int invalidTstCounter = 0;
            for (TimestampToken timestampToken : timestamps) {
                assertTrue(timestampToken.isProcessed());
                assertTrue(timestampToken.isMessageImprintDataFound());
                if (timestampToken.isMessageImprintDataIntact()) {
                    ++validTstCounter;
                } else {
                    ++invalidTstCounter;
                }
            }
            assertEquals(2, validTstCounter);
            assertEquals(1, invalidTstCounter);
        }
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, diagnosticData.getTimestampList().size());

        int validTstCounter = 0;
        int invalidTstCounter = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertEquals(TimestampType.EVIDENCE_RECORD_TIMESTAMP, timestampWrapper.getType());
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            if (timestampWrapper.isMessageImprintDataIntact()) {
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
                ++validTstCounter;
            } else {
                assertTrue(timestampWrapper.isSignatureIntact());
                assertFalse(timestampWrapper.isSignatureValid());
                ++invalidTstCounter;
            }
        }
        assertEquals(2, validTstCounter);
        assertEquals(1, invalidTstCounter);

        assertEquals(timestampList.get(1).getDigestAlgoAndValue().getDigestMethod(),
                timestampList.get(2).getDigestAlgoAndValue().getDigestMethod());
        assertArrayEquals(timestampList.get(1).getDigestAlgoAndValue().getDigestValue(),
                timestampList.get(2).getDigestAlgoAndValue().getDigestValue());
    }

}