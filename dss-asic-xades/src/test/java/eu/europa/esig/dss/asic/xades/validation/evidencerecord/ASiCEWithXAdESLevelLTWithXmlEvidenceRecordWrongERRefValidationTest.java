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
package eu.europa.esig.dss.asic.xades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithXAdESLevelLTWithXmlEvidenceRecordWrongERRefValidationTest extends AbstractASiCEWithXAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/xades-lt-with-er-multi-data-wrong-er-reference.sce");
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 4;
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertEquals(1, Utils.collectionSize(detachedEvidenceRecords));
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);

        int validRefsCounter = 0;
        int invalidRefsCounter = 0;
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(4, Utils.collectionSize(referenceValidationList));
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            if (referenceValidation.isIntact()) {
                ++validRefsCounter;
            } else {
                ++invalidRefsCounter;
            }
        }
        assertEquals(3, validRefsCounter);
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
            assertFalse(timestampToken.isMessageImprintDataIntact());

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
        assertEquals(4, Utils.collectionSize(digestMatcherList));
        for (XmlDigestMatcher digestMatcher : digestMatcherList) {
            assertTrue(digestMatcher.isDataFound());
            if (digestMatcher.isDataIntact()) {
                ++validRefsCounter;
            } else {
                ++invalidRefsCounter;
            }
        }
        assertEquals(3, validRefsCounter);
        assertEquals(1, invalidRefsCounter);
    }

    @Override
    protected void verifyCertificateSourceData(SignatureCertificateSource certificateSource, FoundCertificatesProxy foundCertificates) {
        // skip (time-stamp contains multiple sign-cert refs)
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<String> contentFiles = diagnosticData.getContainerInfo().getContentFiles();

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecords));

            for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {

                int tstCounter = 0;

                List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
                for (TimestampWrapper timestamp : timestamps) {
                    assertNotNull(timestamp.getType());
                    assertNotNull(timestamp.getArchiveTimestampType());
                    assertNotNull(timestamp.getEvidenceRecordTimestampType());

                    assertTrue(timestamp.isMessageImprintDataFound());
                    assertFalse(timestamp.isMessageImprintDataIntact());
                    assertTrue(timestamp.isSignatureIntact());
                    assertFalse(timestamp.isSignatureValid());

                    List<XmlSignatureScope> timestampScopes = timestamp.getTimestampScopes();
                    assertFalse(Utils.isCollectionNotEmpty(timestampScopes));

                    boolean coversEvidenceRecord = false;
                    boolean coversSignature = false;
                    boolean coversSignedData = false;
                    boolean coversCertificates = false;
                    boolean coversRevocationData = false;
                    boolean coversTimestamps = false;
                    List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
                    assertTrue(Utils.isCollectionNotEmpty(timestampedObjects));
                    for (XmlTimestampedObject reference : timestampedObjects) {
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
                        } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                            coversEvidenceRecord = true;
                        }
                    }

                    assertEquals(contentFiles.size(), timestampedObjects.stream()
                            .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).count());

                    assertTrue(coversEvidenceRecord);
                    assertTrue(coversSignature);
                    assertTrue(coversSignedData);
                    assertTrue(coversCertificates);
                    if (SignatureLevel.XAdES_BASELINE_B != signature.getSignatureFormat()) {
                        assertTrue(coversTimestamps);
                    } else if (SignatureLevel.XAdES_BASELINE_T != signature.getSignatureFormat()) {
                        assertTrue(coversRevocationData);
                    }

                    if (tstCounter > 0) {
                        List<XmlDigestMatcher> tstDigestMatcherList = timestamp.getDigestMatchers();
                        assertTrue(Utils.isCollectionNotEmpty(tstDigestMatcherList));

                        boolean archiveTstDigestFound = false;
                        boolean archiveTstSequenceDigestFound = false;
                        for (XmlDigestMatcher digestMatcher : tstDigestMatcherList) {
                            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(digestMatcher.getType())) {
                                archiveTstDigestFound = true;
                            } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE.equals(digestMatcher.getType())) {
                                archiveTstSequenceDigestFound = true;
                            }
                            assertTrue(digestMatcher.isDataFound());
                            assertTrue(digestMatcher.isDataIntact());
                        }

                        assertEquals(EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP == timestamp.getEvidenceRecordTimestampType(), archiveTstDigestFound);
                        assertEquals(EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestamp.getEvidenceRecordTimestampType(), archiveTstSequenceDigestFound);

                    } else {
                        assertEquals(EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP, timestamp.getEvidenceRecordTimestampType());
                    }

                    ++tstCounter;
                }
            }
        }
    }

    @Override
    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        // skip
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            assertTrue(Utils.isCollectionNotEmpty(signatureEvidenceRecords));
            assertEquals(1, Utils.collectionSize(signatureEvidenceRecords));

            XmlEvidenceRecord xmlEvidenceRecord = signatureEvidenceRecords.get(0);
            assertNotNull(xmlEvidenceRecord.getPOETime());
            assertEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());
            assertEquals(SubIndication.HASH_FAILURE, xmlEvidenceRecord.getSubIndication());

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
            assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(evidenceRecordScopes));

            boolean sigNameFound = false;
            for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
                if (simpleReport.getTokenFilename(sigId).equals(evidenceRecordScope.getName())) {
                    sigNameFound = true;
                }
            }
            assertTrue(sigNameFound);

            XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
            assertNotNull(timestamps);
            assertEquals(1, Utils.collectionSize(timestamps.getTimestamp()));

            XmlTimestamp xmlTimestamp = timestamps.getTimestamp().get(0);
            assertEquals(Indication.FAILED, xmlTimestamp.getIndication());
            assertEquals(SubIndication.HASH_FAILURE, xmlTimestamp.getSubIndication());

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
            assertFalse(Utils.isCollectionNotEmpty(timestampScopes));
        }
    }

}
