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
package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelERSTwoERMixedTypesTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelBWithEmbeddedEvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/C-E-ERS-two-er-mixed.p7m"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_BASELINE_LT, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(2, evidenceRecords.size());

        int internalERCounter = 0;
        int externalERCounter = 0;
        for (EvidenceRecordWrapper evidenceRecordWrapper : evidenceRecords) {
            if (EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD == evidenceRecordWrapper.getIncorporationType()) {
                ++internalERCounter;
            } else if (EvidenceRecordIncorporationType.EXTERNAL_EVIDENCE_RECORD == evidenceRecordWrapper.getIncorporationType()) {
                ++externalERCounter;
            }
        }
        assertEquals(1, internalERCounter);
        assertEquals(1, externalERCounter);
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        int internalERCounter = 0;
        int externalERCounter = 0;

        for (EvidenceRecordWrapper evidenceRecordWrapper : diagnosticData.getEvidenceRecords()) {
            if (EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD == evidenceRecordWrapper.getIncorporationType()) {
                List<XmlDigestMatcher> digestMatchers = evidenceRecordWrapper.getDigestMatchers();
                assertEquals(1, digestMatchers.size());

                XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
                assertEquals(DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE, xmlDigestMatcher.getType());
                assertTrue(xmlDigestMatcher.isDataFound());
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals(DigestAlgorithm.SHA256, xmlDigestMatcher.getDigestMethod());
                assertNotNull(xmlDigestMatcher.getDigestValue());

                ++internalERCounter;
            } else if (EvidenceRecordIncorporationType.EXTERNAL_EVIDENCE_RECORD == evidenceRecordWrapper.getIncorporationType()) {
                List<XmlDigestMatcher> digestMatchers = evidenceRecordWrapper.getDigestMatchers();
                assertEquals(2, digestMatchers.size());

                int masterSigDMCounter = 0;
                int refMCounter = 0;
                for (XmlDigestMatcher digestMatcher : digestMatchers) {
                    if (DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE == digestMatcher.getType()) {
                        assertTrue(digestMatcher.isDataFound());
                        assertTrue(digestMatcher.isDataIntact());
                        ++masterSigDMCounter;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                        assertFalse(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        ++refMCounter;
                    }
                }
                assertEquals(1, masterSigDMCounter);
                assertEquals(1, refMCounter);

                ++externalERCounter;
            }
        }
        assertEquals(1, internalERCounter);
        assertEquals(1, externalERCounter);
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(2, evidenceRecords.size());

        for (EvidenceRecordWrapper evidenceRecordWrapper : evidenceRecords) {
            List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
            assertEquals(1, timestampList.size());

            TimestampWrapper timestampWrapper = timestampList.get(0);
            assertNotNull(timestampWrapper.getProductionTime());
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());

            assertTrue(timestampWrapper.isSigningCertificateIdentified());
            assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
            assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
        }
    }

}
