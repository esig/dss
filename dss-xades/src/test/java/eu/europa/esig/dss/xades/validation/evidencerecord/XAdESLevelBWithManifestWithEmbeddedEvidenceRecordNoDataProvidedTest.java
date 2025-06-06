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
package eu.europa.esig.dss.xades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelBWithManifestWithEmbeddedEvidenceRecordNoDataProvidedTest extends AbstractXAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-MANIFEST.xml");
    }

    @Override
    protected void checkEvidenceRecordType(EvidenceRecordWrapper evidenceRecord) {
        super.checkEvidenceRecordType(evidenceRecord);

        assertEquals(EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD, evidenceRecord.getEvidenceRecordType());
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        assertEquals(1, evidenceRecordWrapper.getDigestMatchers().size());

        List<XmlDigestMatcher> digestMatchers = evidenceRecordWrapper.getDigestMatchers();
        assertEquals(DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE, digestMatchers.get(0).getType());
        assertFalse(digestMatchers.get(0).isDataFound());
        assertFalse(digestMatchers.get(0).isDataIntact());
        assertNotNull(digestMatchers.get(0).getDigestMethod());
        assertNotNull(digestMatchers.get(0).getDigestValue());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 0;
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertTrue(Utils.isCollectionEmpty(evidenceRecordScopes));
    }

    @Override
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);

        int coversSignatureCounter = 0;
        int coversSignedDataCounter = 0;
        int coversCertificatesCounter = 0;
        int coversRevocationDataCounter = 0;
        int coversTimestampsCounter = 0;
        int coversEvidenceRecordsCounter = 0;

        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
        for (XmlTimestampedObject reference : coveredObjects) {
            if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                ++coversSignatureCounter;
            } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                ++coversSignedDataCounter;
            } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                ++coversCertificatesCounter;
            } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                ++coversRevocationDataCounter;
            } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                ++coversTimestampsCounter;
            } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                ++coversEvidenceRecordsCounter;
            }
        }
        assertEquals(1, coversSignatureCounter);
        assertEquals(1, coversSignedDataCounter);
        assertEquals(2, coversCertificatesCounter);
        assertEquals(0, coversRevocationDataCounter);
        assertEquals(0, coversTimestampsCounter);
        assertEquals(0, coversEvidenceRecordsCounter);

        TimestampWrapper timestamp = evidenceRecord.getTimestampList().get(0);

        coversSignatureCounter = 0;
        coversSignedDataCounter = 0;
        coversCertificatesCounter = 0;
        coversRevocationDataCounter = 0;
        coversTimestampsCounter = 0;
        coversEvidenceRecordsCounter = 0;

        coveredObjects = timestamp.getTimestampedObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
        for (XmlTimestampedObject reference : coveredObjects) {
            if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                ++coversSignatureCounter;
            } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                ++coversSignedDataCounter;
            } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                ++coversCertificatesCounter;
            } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                ++coversRevocationDataCounter;
            } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                ++coversTimestampsCounter;
            } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                ++coversEvidenceRecordsCounter;
            }
        }
        assertEquals(1, coversSignatureCounter);
        assertEquals(1, coversSignedDataCounter);
        assertEquals(2, coversCertificatesCounter);
        assertEquals(0, coversRevocationDataCounter);
        assertEquals(0, coversTimestampsCounter);
        assertEquals(1, coversEvidenceRecordsCounter);
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        assertTrue(Utils.isCollectionEmpty(timestampWrapper.getTimestampScopes()));
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));

        assertEquals(Utils.collectionSize(signatures), coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNATURE == r.getCategory()).count());
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).collect(Collectors.toList())));

        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignedData()));
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        int sigWithErCounter = 0;
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            if (Utils.isCollectionNotEmpty(signatureEvidenceRecords)) {
                ++sigWithErCounter;
            }

            XmlEvidenceRecord evidenceRecord = signatureEvidenceRecords.get(0);
            // skip validation of manifest entries
            assertTrue(evidenceRecord.getAdESValidationDetails().getWarning().stream()
                    .noneMatch(m -> MessageTag.BBB_CV_ER_HASSDOC_ANS.getId().equals(m.getKey())));
            assertNotEquals(Indication.FAILED, simpleReport.getIndication(evidenceRecord.getId()));
        }
        assertEquals(1, sigWithErCounter);
    }

}
