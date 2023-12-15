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
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XmlEvidenceRecordChainRenewalNoHashTreeValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-chain-renewal-no-hashtree.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("da2e47f2-53f4-4610-8210-f0f05d67d0c9".getBytes()));
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
        assertEquals(2, timestamps.size());

        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());

            List<ReferenceValidation> referenceValidations = timestampToken.getReferenceValidations();
            if (Utils.collectionSize(referenceValidations) == 0) {
                assertTrue(timestampToken.isMessageImprintDataFound());
                assertTrue(timestampToken.isMessageImprintDataIntact());
                ++passedTstCounter;

            } else if (Utils.collectionSize(referenceValidations) == 2) {
                assertTrue(timestampToken.isMessageImprintDataFound());
                assertFalse(timestampToken.isMessageImprintDataIntact());

                boolean orphanRefFound = false;
                boolean chainTstFound = false;
                for (ReferenceValidation tstReferenceValidation : referenceValidations) {
                    if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == tstReferenceValidation.getType()) {
                        assertFalse(tstReferenceValidation.isFound());
                        assertFalse(tstReferenceValidation.isIntact());
                        orphanRefFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE == tstReferenceValidation.getType()) {
                        assertTrue(tstReferenceValidation.isFound());
                        assertTrue(tstReferenceValidation.isIntact());
                        chainTstFound = true;
                    }
                }
                assertTrue(orphanRefFound);
                assertTrue(chainTstFound);
                ++failedTstCounter;
            }

        }

        assertEquals(1, passedTstCounter);
        assertEquals(1, failedTstCounter);
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(1, evidenceRecordScopes.size());

        assertEquals(2, diagnosticData.getTimestampList().size());

        boolean initialTstFound = false;
        boolean chainRenewalTstFound = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
            if (digestMatchers.size() == 1) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertEquals(DigestMatcherType.MESSAGE_IMPRINT, digestMatchers.get(0).getType());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
                initialTstFound = true;

                List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
                assertEquals(1, timestampScopes.size());
                assertEquals(evidenceRecordScopes.get(0).getSignerData(), timestampScopes.get(0).getSignerData());

            } else if (digestMatchers.size() == 3) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertFalse(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertFalse(timestampWrapper.isSignatureValid());

                boolean messageImprintFound = false;
                boolean orphanRefFound = false;
                boolean chainTstFound = false;
                for (XmlDigestMatcher digestMatcher : digestMatchers) {
                    if (DigestMatcherType.MESSAGE_IMPRINT == digestMatcher.getType()) {
                        assertTrue(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        messageImprintFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == digestMatcher.getType()) {
                        assertFalse(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        orphanRefFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE == digestMatcher.getType()) {
                        assertTrue(digestMatcher.isDataFound());
                        assertTrue(digestMatcher.isDataIntact());
                        chainTstFound = true;
                    }
                }
                assertTrue(messageImprintFound);
                assertTrue(orphanRefFound);
                assertTrue(chainTstFound);

                List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
                assertEquals(0, timestampScopes.size());

                chainRenewalTstFound = true;
            }
        }
        assertTrue(initialTstFound);
        assertTrue(chainRenewalTstFound);
    }

}
