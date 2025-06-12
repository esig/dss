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
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CAdESLevelERSRenewedHashtreeInvalidTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelBWithEmbeddedEvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/C-E-ERS_renewed_hashtree_invalid.p7m"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_ERS, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        assertEquals(EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD, evidenceRecord.getEvidenceRecordType());
        assertEquals(EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD, evidenceRecord.getIncorporationType());

        boolean coversSignature = false;
        boolean coversSignedData = false;
        boolean coversCertificates = false;
        boolean coversRevocationData = false;
        boolean coversTimestamps = false;
        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
        for (XmlTimestampedObject reference : coveredObjects) {
            if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                coversSignature = true;
            } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                coversSignedData = true;
            } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                coversCertificates = true;
            } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                coversRevocationData = true;
            } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                coversTimestamps = true;
            }
        }
        assertTrue(coversSignature);
        assertTrue(coversSignedData);
        assertTrue(coversCertificates);
        assertTrue(coversTimestamps);
        assertTrue(coversRevocationData);
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
        assertEquals(3, timestampList.size());

        int firstTstCounter = 0;
        int tstRenewalCounter = 0;
        int arcTstChainRenewalCounter = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertNotNull(timestampWrapper.getProductionTime());
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());

            assertTrue(timestampWrapper.isSigningCertificateIdentified());
            assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
            assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());

            boolean messageImprintFound = false;
            boolean masterSigDMFound = false;
            boolean tstRenewalDMFound = false;
            for (XmlDigestMatcher xmlDigestMatcher : timestampWrapper.getDigestMatchers()) {
                if (DigestMatcherType.MESSAGE_IMPRINT == xmlDigestMatcher.getType()) {
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertTrue(xmlDigestMatcher.isDataIntact());
                    messageImprintFound = true;
                } else if (DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE == xmlDigestMatcher.getType()) {
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertFalse(xmlDigestMatcher.isDataIntact());
                    masterSigDMFound = true;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP == xmlDigestMatcher.getType()) {
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertTrue(xmlDigestMatcher.isDataIntact());
                    tstRenewalDMFound = true;
                } else {
                    fail(String.format("Not expected type : '%s'", xmlDigestMatcher.getType()));
                }
            }
            assertTrue(messageImprintFound);

            if (masterSigDMFound) {
                assertFalse(timestampWrapper.isSignatureValid());
                assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
                ++arcTstChainRenewalCounter;
            } else if (tstRenewalDMFound) {
                assertTrue(timestampWrapper.isSignatureValid());
                assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
                ++tstRenewalCounter;
            } else {
                assertTrue(timestampWrapper.isSignatureValid());
                assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
                ++firstTstCounter;
            }
        }
        assertEquals(1, firstTstCounter);
        assertEquals(1, tstRenewalCounter);
        assertEquals(1, arcTstChainRenewalCounter);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureEvidenceRecords.size());

        XmlEvidenceRecord evidenceRecord = signatureEvidenceRecords.get(0);
        assertEquals(Indication.INDETERMINATE, evidenceRecord.getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, evidenceRecord.getSubIndication());

        int validTstCounter = 0;
        int invalidTstCounter = 0;
        for (XmlTimestamp timestamp : evidenceRecord.getTimestamps().getTimestamp()) {
            if (Indication.FAILED == timestamp.getIndication()) {
                assertEquals(SubIndication.HASH_FAILURE, timestamp.getSubIndication());
                ++invalidTstCounter;
            } else {
                assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, timestamp.getSubIndication());
                ++validTstCounter;
            }
        }
        assertEquals(2, validTstCounter);
        assertEquals(1, invalidTstCounter);
    }

}
