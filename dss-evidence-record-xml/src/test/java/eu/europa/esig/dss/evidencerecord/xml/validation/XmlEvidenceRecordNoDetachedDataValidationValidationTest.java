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
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XmlEvidenceRecordNoDetachedDataValidationValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-simple.xml");
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);
        List<ReferenceValidation> referenceValidations = evidenceRecord.getReferenceValidation();
        assertEquals(1, referenceValidations.size());

        assertEquals(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE, referenceValidations.get(0).getType());
        assertFalse(referenceValidations.get(0).isFound());
        assertFalse(referenceValidations.get(0).isIntact());
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        List<XmlDigestMatcher> digestMatchers = evidenceRecordWrapper.getDigestMatchers();
        assertEquals(1, digestMatchers.size());

        assertEquals(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE, digestMatchers.get(0).getType());
        assertFalse(digestMatchers.get(0).isDataFound());
        assertFalse(digestMatchers.get(0).isDataIntact());
    }

    @Override
    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecordWrapper.getEvidenceRecordScopes()));
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().get(0);
        assertEquals(1, timestampWrapper.getTimestampedObjects().size());
        assertEquals(0, timestampWrapper.getTimestampedSignedData().size());
        assertEquals(1, timestampWrapper.getTimestampedEvidenceRecords().size());
    }

    @Override
    protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
        // skip
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstEvidenceRecordId()));
    }

}
