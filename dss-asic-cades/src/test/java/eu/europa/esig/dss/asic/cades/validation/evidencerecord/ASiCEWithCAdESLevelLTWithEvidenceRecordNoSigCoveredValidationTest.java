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
package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithCAdESLevelLTWithEvidenceRecordNoSigCoveredValidationTest extends AbstractASiCEWithCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-er-no-sig.sce");
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2; // two docs covered
    }

    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));

        assertEquals(0, coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNATURE == r.getCategory()).count());
        assertEquals(2, coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).count());
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
            for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
                List<XmlSignatureScope> evidenceRecordScopes = evidenceRecord.getEvidenceRecordScopes();
                assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(evidenceRecordScopes));

                boolean sigFileFound = false;
                for (XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                    assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
                    if (signature.getSignatureFilename().equals(evidenceRecordScope.getName())) {
                        sigFileFound = true;
                    }
                }
                assertFalse(sigFileFound);
            }
        }
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecords));

            for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {

                List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
                for (TimestampWrapper timestamp : timestamps) {
                    assertTrue(timestamp.isMessageImprintDataFound());
                    assertTrue(timestamp.isMessageImprintDataIntact());
                    assertTrue(timestamp.isSignatureIntact());
                    assertTrue(timestamp.isSignatureValid());

                    List<XmlSignatureScope> timestampScopes = timestamp.getTimestampScopes();
                    assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(timestampScopes));

                    boolean sigFileFound = false;
                    for (XmlSignatureScope tstScope : timestampScopes) {
                        assertEquals(SignatureScopeType.FULL, tstScope.getScope());
                        if (signature.getSignatureFilename().equals(tstScope.getName())) {
                            sigFileFound = true;
                        }
                    }
                    assertFalse(sigFileFound);

                    List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();

                    assertEquals(2, timestampedObjects.stream()
                            .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).count());
                }
            }
        }
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        List<String> signatureIdList = simpleReport.getSignatureIdList();
        assertEquals(1, signatureIdList.size());

        String sigId = signatureIdList.get(0);
        assertEquals(0, Utils.collectionSize(simpleReport.getSignatureEvidenceRecords(sigId)));

        List<String> evidenceRecordIdList = simpleReport.getEvidenceRecordIdList();
        assertEquals(1, evidenceRecordIdList.size());

        String evRecId = evidenceRecordIdList.get(0);
        XmlEvidenceRecord xmlEvidenceRecord = simpleReport.getEvidenceRecordById(evRecId);
        assertNotNull(xmlEvidenceRecord);

        assertNotNull(xmlEvidenceRecord.getPOETime());
        assertNotEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());

        List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
        assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(evidenceRecordScopes));

        boolean sigFileFound = false;
        for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
            assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
            if (simpleReport.getTokenFilename(sigId).equals(evidenceRecordScope.getName())) {
                sigFileFound = true;
            }
        }
        assertFalse(sigFileFound);

        XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
        assertNotNull(timestamps);
        assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

        for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
            assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
            assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(timestampScopes));

            for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope tstScope : timestampScopes) {
                assertEquals(SignatureScopeType.FULL, tstScope.getScope());
                if (simpleReport.getTokenFilename(sigId).equals(tstScope.getName())) {
                    sigFileFound = true;
                }
            }
            assertFalse(sigFileFound);
        }
    }

}
