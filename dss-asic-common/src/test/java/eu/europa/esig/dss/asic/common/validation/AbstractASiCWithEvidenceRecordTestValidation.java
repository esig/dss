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
package eu.europa.esig.dss.asic.common.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.test.validation.AbstractDocumentTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCWithEvidenceRecordTestValidation extends AbstractDocumentTestValidation {

    @Override
    protected List<AdvancedSignature> getSignatures(DocumentValidator validator) {
        return Collections.emptyList();
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        assertTrue(Utils.isCollectionEmpty(signatures));
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatures()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatureIdList()));
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertNotNull(diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
        if (ASiCContainerType.ASiC_E == diagnosticData.getContainerInfo().getContainerType()) {
            assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getManifestFiles()));
        }
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

            int tstCounter = 0;

            List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
            for (TimestampToken timestampToken : timestamps) {
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
                        } else if (allArchiveDataObjectsProvidedToValidation() ||
                                DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType()) {
                            assertTrue(referenceValidation.isFound());
                            assertTrue(referenceValidation.isIntact());
                        }
                    }

                    if (tstReferenceValidationList.size() == 1) {
                        assertTrue(archiveTstDigestFound);
                    } else {
                        assertTrue(archiveTstSequenceDigestFound);
                    }

                }

                ++tstCounter;
            }
        }
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestamps(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        List<String> contentFiles = containerInfo.getContentFiles();

        for (EvidenceRecordWrapper evidenceRecord : diagnosticData.getEvidenceRecords()) {

            int tstCounter = 0;

            List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
            for (TimestampWrapper timestamp : timestamps) {
                assertTrue(timestamp.isMessageImprintDataFound());
                assertTrue(timestamp.isMessageImprintDataIntact());
                assertTrue(timestamp.isSignatureIntact());
                assertTrue(timestamp.isSignatureValid());

                List<XmlSignatureScope> timestampScopes = timestamp.getTimestampScopes();
                assertEquals(contentFiles.size(), timestampScopes.size());

                List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
                assertTrue(Utils.isCollectionNotEmpty(timestampedObjects));

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
                        } else if ((allArchiveDataObjectsProvidedToValidation() && tstCoversOnlyCurrentHashTreeData()) ||
                                DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != digestMatcher.getType()) {
                            assertTrue(digestMatcher.isDataFound());
                            assertTrue(digestMatcher.isDataFound());
                        }
                    }

                    if (tstDigestMatcherList.size() == 2) { // arc-tst + message-digest
                        assertTrue(archiveTstDigestFound);
                    } else if (tstCoversOnlyCurrentHashTreeData()) {
                        assertTrue(archiveTstSequenceDigestFound);
                    }
                }

                ++tstCounter;
            }
        }
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        assertNotNull(simpleReport);

        for (String erId : simpleReport.getEvidenceRecordIdList()) {
            XmlEvidenceRecord xmlEvidenceRecord = simpleReport.getEvidenceRecordById(erId);
            assertNotNull(simpleReport.getEvidenceRecordPOE(erId));
            assertNotEquals(Indication.FAILED, simpleReport.getIndication(erId));

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecordScopes));

            XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
            assertNotNull(timestamps);
            assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

            for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
                assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

                List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
                assertTrue(Utils.isCollectionNotEmpty(timestampScopes));
            }
        }

        assertNotNull(simpleReport.getValidationTime());
    }

    @Override
    protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
        // TODO : implement ETSI VR support
    }

    protected boolean tstCoversOnlyCurrentHashTreeData() {
        return true;
    }

}
