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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
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
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESLevelLTWithEvidenceRecordsUnsignedEntriesValidationTest extends AbstractASiCEWithCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-er-unsigned-manifest-entries.sce");
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertTrue(Utils.isCollectionNotEmpty(detachedEvidenceRecords));

        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);

        int validEntriesCounter = 0;
        int invalidEntriesCounter = 0;
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            if (referenceValidation.isIntact()) {
                ++validEntriesCounter;
            } else {
                ++invalidEntriesCounter;
            }
        }
        assertEquals(2, validEntriesCounter);
        assertEquals(2, invalidEntriesCounter);

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
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);

        int validEntriesCounter = 0;
        int invalidEntriesCounter = 0;
        List<XmlDigestMatcher> digestMatchers = evidenceRecord.getDigestMatchers();
        assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, digestMatcher.getType());
            assertNotNull(digestMatcher.getDigestMethod());
            assertNotNull(digestMatcher.getDigestValue());
            assertTrue(digestMatcher.isDataFound());
            if (digestMatcher.isDataIntact()) {
                ++validEntriesCounter;
            } else {
                ++invalidEntriesCounter;
            }
        }
        assertEquals(2, validEntriesCounter);
        assertEquals(2, invalidEntriesCounter);
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
            for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {

                XmlManifestFile erManifest = null;
                for (XmlManifestFile xmlManifestFile : containerInfo.getManifestFiles()) {
                    if (xmlManifestFile.getSignatureFilename().equals(evidenceRecord.getFilename())) {
                        erManifest = xmlManifestFile;
                    }
                }
                assertNotNull(erManifest);

                List<XmlSignatureScope> evidenceRecordScopes = evidenceRecord.getEvidenceRecordScopes();
                assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(evidenceRecordScopes));

                boolean sigFileFound = false;
                for (XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                    assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
                    if (signature.getFilename().equals(evidenceRecordScope.getName())) {
                        sigFileFound = true;
                    }
                }
                assertTrue(sigFileFound);
            }
        }
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
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
                    assertTrue(timestamp.isMessageImprintDataIntact());
                    assertTrue(timestamp.isSignatureIntact());
                    assertTrue(timestamp.isSignatureValid());

                    List<XmlSignatureScope> timestampScopes = timestamp.getTimestampScopes();
                    assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(timestampScopes));

                    boolean sigFileFound = false;
                    for (XmlSignatureScope tstScope : timestampScopes) {
                        assertEquals(SignatureScopeType.FULL, tstScope.getScope());
                        if (signature.getFilename().equals(tstScope.getName())) {
                            sigFileFound = true;
                        }
                    }
                    assertTrue(sigFileFound);

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

                    assertEquals(getNumberOfExpectedEvidenceScopes(), timestampedObjects.stream()
                            .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).count()); // created additional objects for "invalid" sig ref (no POE provided)

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
    protected void verifySimpleReport(SimpleReport simpleReport) {
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            assertTrue(Utils.isCollectionNotEmpty(signatureEvidenceRecords));

            for (XmlEvidenceRecord xmlEvidenceRecord : signatureEvidenceRecords) {
                assertNotNull(xmlEvidenceRecord.getPOETime());
                assertEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());
                assertEquals(SubIndication.HASH_FAILURE, xmlEvidenceRecord.getSubIndication());

                List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
                assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(evidenceRecordScopes));

                boolean sigFileFound = false;
                for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                    assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
                    if (simpleReport.getTokenFilename(sigId).equals(evidenceRecordScope.getName())) {
                        sigFileFound = true;
                    }
                }
                assertTrue(sigFileFound);

                XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
                assertNotNull(timestamps);
                assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

                for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
                    assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

                    List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
                    assertEquals(Utils.collectionSize(evidenceRecordScopes), Utils.collectionSize(timestampScopes));

                    for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope tstScope : timestampScopes) {
                        assertEquals(SignatureScopeType.FULL, tstScope.getScope());
                        if (simpleReport.getTokenFilename(sigId).equals(tstScope.getName())) {
                            sigFileFound = true;
                        }
                    }
                    assertTrue(sigFileFound);
                }

            }
        }
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 4;
    }

}
