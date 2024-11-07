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

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithAsn1EvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESAsn1EvidenceRecordNoHashTreeNoManifestValidationTest extends AbstractASiCWithAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-no-hashtree-no-manifest.sce");
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertTrue(Utils.isCollectionNotEmpty(detachedEvidenceRecords));

        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(1, referenceValidationList.size());

        int foundArchiveObjectCounter = 0;
        int notFoundArchiveObjectCounter = 0;
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == referenceValidation.getType()) {
                assertNotNull(referenceValidation.getDocumentName());
                assertTrue(referenceValidation.isFound());
                assertTrue(referenceValidation.isIntact());
                ++foundArchiveObjectCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == referenceValidation.getType()) {
                assertNull(referenceValidation.getDocumentName());
                assertFalse(referenceValidation.isFound());
                assertFalse(referenceValidation.isIntact());
                ++notFoundArchiveObjectCounter;
            }
        }
        assertEquals(0, foundArchiveObjectCounter);
        assertEquals(1, notFoundArchiveObjectCounter);

        List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
        assertFalse(Utils.isCollectionNotEmpty(timestampedReferences));

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        assertEquals(1, Utils.collectionSize(timestamps));

        TimestampToken originalTst = timestamps.get(0);
        assertTrue(originalTst.isProcessed());
        assertTrue(originalTst.isMessageImprintDataFound());
        assertFalse(originalTst.isMessageImprintDataIntact());
        assertEquals(0, Utils.collectionSize(originalTst.getReferenceValidations()));
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
        TimestampWrapper timestamp = timestamps.get(0);
        assertTrue(timestamp.isMessageImprintDataFound());
        assertFalse(timestamp.isMessageImprintDataIntact());
        assertTrue(timestamp.isSignatureIntact());
        assertFalse(timestamp.isSignatureValid());

        List<XmlSignatureScope> timestampScopes = timestamp.getTimestampScopes();
        assertFalse(Utils.isCollectionNotEmpty(timestampScopes));

        List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
        assertTrue(Utils.isCollectionNotEmpty(timestampedObjects));
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getEvidenceRecordScopes()));
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredObjects()));
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertNotNull(diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
        assertFalse(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getManifestFiles()));
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        XmlEvidenceRecord evidenceRecord = simpleReport.getEvidenceRecordById(simpleReport.getFirstEvidenceRecordId());
        assertNotNull(evidenceRecord);
        assertEquals(Indication.INDETERMINATE, evidenceRecord.getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, evidenceRecord.getSubIndication());
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected boolean tstCoversOnlyCurrentHashTreeData() {
        return false;
    }

}
