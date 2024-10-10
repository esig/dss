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
package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureWithERValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void sigWithERValidationTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/sig-with-er-valid.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        List<XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureTimestamps.size());
        assertEquals(Indication.PASSED, signatureTimestamps.get(0).getIndication());

        List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureEvidenceRecords.size());
        assertEquals(Indication.PASSED, signatureEvidenceRecords.get(0).getIndication());

        XmlTimestamps timestamps = signatureEvidenceRecords.get(0).getTimestamps();
        assertNotNull(timestamps);
        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> evidenceRecordTimestamps = timestamps.getTimestamp();
        assertEquals(2, evidenceRecordTimestamps.size());
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : evidenceRecordTimestamps) {
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
        }

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(signatureTimestamps.get(0).getId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataTimestampValidationIndication(signatureTimestamps.get(0).getId()));

        int processedTimestampsCounter = 0;
        int skippedTimestampsCounter = 0;
        for (eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            if (tstBBB != null) {
                ++processedTimestampsCounter;
            } else {
                ++skippedTimestampsCounter;
            }
        }
        assertEquals(3, processedTimestampsCounter);
        assertEquals(0, skippedTimestampsCounter);

        assertEquals(Indication.PASSED, detailedReport.getEvidenceRecordValidationIndication(signatureEvidenceRecords.get(0).getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord = detailedReport.getXmlEvidenceRecordById(signatureEvidenceRecords.get(0).getId());
        assertEquals(Indication.PASSED, xmlEvidenceRecord.getConclusion().getIndication());

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertEquals(Indication.PASSED, validationProcessEvidenceRecord.getConclusion().getIndication());

        int dataObjectFoundCheckCounter = 0;
        int dataObjectIntactCheckCounter = 0;
        int tstValidationConclusiveCheckCounter = 0;
        int cryptoConstraintsCheckCounter = 0;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectFoundCheckCounter;
            } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectIntactCheckCounter;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++tstValidationConclusiveCheckCounter;
            } else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++cryptoConstraintsCheckCounter;
            }
        }
        assertEquals(1, dataObjectFoundCheckCounter);
        assertEquals(1, dataObjectIntactCheckCounter);
        assertEquals(2, tstValidationConclusiveCheckCounter);
        assertEquals(1, cryptoConstraintsCheckCounter);

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean evidenceRecordCheckFound = false;
        boolean ltLevelAcceptableCheckFound = false;
        boolean tstValidationCheckFound = false;
        boolean pastSignatureValidationCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IRERVPC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                evidenceRecordCheckFound = true;
            } else if (MessageTag.ARCH_LTVV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ltLevelAcceptableCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                tstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                pastSignatureValidationCheckFound = true;
            }
        }
        assertTrue(evidenceRecordCheckFound);
        assertTrue(ltLevelAcceptableCheckFound);
        assertTrue(tstValidationCheckFound);
        assertTrue(pastSignatureValidationCheckFound);
    }

    @Test
    void sigWithBrokenERValidationTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/sig-with-er-valid.xml"));
        assertNotNull(diagnosticData);

        XmlEvidenceRecord xmlEvidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        xmlEvidenceRecord.getDigestMatchers().get(0).setDataIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureTimestamps.size());
        assertEquals(Indication.INDETERMINATE, signatureTimestamps.get(0).getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureTimestamps.get(0).getSubIndication());

        List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureEvidenceRecords.size());
        assertEquals(Indication.FAILED, signatureEvidenceRecords.get(0).getIndication());
        assertEquals(SubIndication.HASH_FAILURE, signatureEvidenceRecords.get(0).getSubIndication());

        XmlTimestamps timestamps = signatureEvidenceRecords.get(0).getTimestamps();
        assertNotNull(timestamps);
        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> evidenceRecordTimestamps = timestamps.getTimestamp();
        assertEquals(2, evidenceRecordTimestamps.size());
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : evidenceRecordTimestamps) {
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
        }

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(signatureTimestamps.get(0).getId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataTimestampValidationIndication(signatureTimestamps.get(0).getId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getArchiveDataTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

        int processedTimestampsCounter = 0;
        int skippedTimestampsCounter = 0;
        for (eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            if (tstBBB != null) {
                ++processedTimestampsCounter;
            } else {
                ++skippedTimestampsCounter;
            }
        }
        assertEquals(3, processedTimestampsCounter);
        assertEquals(0, skippedTimestampsCounter);

        assertEquals(Indication.FAILED, detailedReport.getEvidenceRecordValidationIndication(signatureEvidenceRecords.get(0).getId()));
        assertEquals(SubIndication.HASH_FAILURE, detailedReport.getEvidenceRecordValidationSubIndication(signatureEvidenceRecords.get(0).getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord evidenceRecord = detailedReport.getXmlEvidenceRecordById(signatureEvidenceRecords.get(0).getId());
        assertEquals(Indication.FAILED, evidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, evidenceRecord.getConclusion().getSubIndication());

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = evidenceRecord.getValidationProcessEvidenceRecord();
        assertEquals(Indication.FAILED, validationProcessEvidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, validationProcessEvidenceRecord.getConclusion().getSubIndication());

        int dataObjectFoundCheckCounter = 0;
        int dataObjectIntactCheckCounter = 0;
        int tstValidationConclusiveCheckCounter = 0;
        int cryptoConstraintsCheckCounter = 0;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectFoundCheckCounter;
            } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_CV_IRDOI_ANS.getId(), xmlConstraint.getError().getKey());
                ++dataObjectIntactCheckCounter;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++tstValidationConclusiveCheckCounter;
            } else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++cryptoConstraintsCheckCounter;
            }
        }
        assertEquals(1, dataObjectFoundCheckCounter);
        assertEquals(1, dataObjectIntactCheckCounter);
        assertEquals(0, tstValidationConclusiveCheckCounter);
        assertEquals(0, cryptoConstraintsCheckCounter);

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessArchivalData.getConclusion().getSubIndication());

        boolean evidenceRecordCheckFound = false;
        boolean ltLevelAcceptableCheckFound = false;
        boolean tstValidationCheckFound = false;
        boolean pastSignatureValidationCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IRERVPC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.ADEST_IRERVPC_ANS.getId(), xmlConstraint.getWarning().getKey());
                evidenceRecordCheckFound = true;
            } else if (MessageTag.ARCH_LTVV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ltLevelAcceptableCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                tstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
                pastSignatureValidationCheckFound = true;
            }
        }
        assertTrue(evidenceRecordCheckFound);
        assertTrue(ltLevelAcceptableCheckFound);
        assertTrue(tstValidationCheckFound);
        assertTrue(pastSignatureValidationCheckFound);
    }

    @Test
    void sigWithBrokenERFirstTimestampValidationTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/sig-with-er-valid.xml"));
        assertNotNull(diagnosticData);

        XmlEvidenceRecord xmlEvidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp xmlERTimestamp = xmlEvidenceRecord.getEvidenceRecordTimestamps().get(0).getTimestamp();
        xmlERTimestamp.getDigestMatchers().get(0).setDataIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureTimestamps.size());
        assertEquals(Indication.INDETERMINATE, signatureTimestamps.get(0).getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureTimestamps.get(0).getSubIndication());

        List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureEvidenceRecords.size());
        assertEquals(Indication.FAILED, signatureEvidenceRecords.get(0).getIndication());
        assertEquals(SubIndication.HASH_FAILURE, signatureEvidenceRecords.get(0).getSubIndication());

        XmlTimestamps timestamps = signatureEvidenceRecords.get(0).getTimestamps();
        assertNotNull(timestamps);
        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> evidenceRecordTimestamps = timestamps.getTimestamp();
        assertEquals(2, evidenceRecordTimestamps.size());

        assertEquals(Indication.FAILED, evidenceRecordTimestamps.get(0).getIndication());
        assertEquals(SubIndication.HASH_FAILURE, evidenceRecordTimestamps.get(0).getSubIndication());

        assertEquals(Indication.PASSED, evidenceRecordTimestamps.get(1).getIndication());

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(signatureTimestamps.get(0).getId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataTimestampValidationIndication(signatureTimestamps.get(0).getId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getArchiveDataTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

        int processedTimestampsCounter = 0;
        int skippedTimestampsCounter = 0;
        for (eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            if (tstBBB != null) {
                ++processedTimestampsCounter;
            } else {
                ++skippedTimestampsCounter;
            }
        }
        assertEquals(3, processedTimestampsCounter);
        assertEquals(0, skippedTimestampsCounter);

        assertEquals(Indication.FAILED, detailedReport.getEvidenceRecordValidationIndication(signatureEvidenceRecords.get(0).getId()));
        assertEquals(SubIndication.HASH_FAILURE, detailedReport.getEvidenceRecordValidationSubIndication(signatureEvidenceRecords.get(0).getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord evidenceRecord = detailedReport.getXmlEvidenceRecordById(signatureEvidenceRecords.get(0).getId());
        assertEquals(Indication.FAILED, evidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, evidenceRecord.getConclusion().getSubIndication());

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = evidenceRecord.getValidationProcessEvidenceRecord();
        assertEquals(Indication.FAILED, validationProcessEvidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, validationProcessEvidenceRecord.getConclusion().getSubIndication());

        int dataObjectFoundCheckCounter = 0;
        int dataObjectIntactCheckCounter = 0;
        int tstValidationConclusiveCheckCounter = 0;
        int cryptoConstraintsCheckCounter = 0;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectFoundCheckCounter;
            } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectIntactCheckCounter;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getError().getKey());
                ++tstValidationConclusiveCheckCounter;
            } else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++cryptoConstraintsCheckCounter;
            }
        }
        assertEquals(1, dataObjectFoundCheckCounter);
        assertEquals(1, dataObjectIntactCheckCounter);
        assertEquals(1, tstValidationConclusiveCheckCounter);
        assertEquals(0, cryptoConstraintsCheckCounter);

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessArchivalData.getConclusion().getSubIndication());

        boolean evidenceRecordCheckFound = false;
        boolean ltLevelAcceptableCheckFound = false;
        boolean tstValidationCheckFound = false;
        boolean pastSignatureValidationCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IRERVPC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.ADEST_IRERVPC_ANS.getId(), xmlConstraint.getWarning().getKey());
                evidenceRecordCheckFound = true;
            } else if (MessageTag.ARCH_LTVV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ltLevelAcceptableCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                tstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
                pastSignatureValidationCheckFound = true;
            }
        }
        assertTrue(evidenceRecordCheckFound);
        assertTrue(ltLevelAcceptableCheckFound);
        assertTrue(tstValidationCheckFound);
        assertTrue(pastSignatureValidationCheckFound);
    }

    @Test
    void sigWithBrokenERSecondTimestampValidationTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/sig-with-er-valid.xml"));
        assertNotNull(diagnosticData);

        XmlEvidenceRecord xmlEvidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp xmlERTimestamp = xmlEvidenceRecord.getEvidenceRecordTimestamps().get(1).getTimestamp();
        xmlERTimestamp.getDigestMatchers().get(0).setDataIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureTimestamps.size());
        assertEquals(Indication.INDETERMINATE, signatureTimestamps.get(0).getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureTimestamps.get(0).getSubIndication());

        List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureEvidenceRecords.size());
        assertEquals(Indication.FAILED, signatureEvidenceRecords.get(0).getIndication());
        assertEquals(SubIndication.HASH_FAILURE, signatureEvidenceRecords.get(0).getSubIndication());

        XmlTimestamps timestamps = signatureEvidenceRecords.get(0).getTimestamps();
        assertNotNull(timestamps);
        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> evidenceRecordTimestamps = timestamps.getTimestamp();
        assertEquals(2, evidenceRecordTimestamps.size());

        assertEquals(Indication.PASSED, evidenceRecordTimestamps.get(0).getIndication());

        assertEquals(Indication.FAILED, evidenceRecordTimestamps.get(1).getIndication());
        assertEquals(SubIndication.HASH_FAILURE, evidenceRecordTimestamps.get(1).getSubIndication());

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(signatureTimestamps.get(0).getId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataTimestampValidationIndication(signatureTimestamps.get(0).getId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getArchiveDataTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

        int processedTimestampsCounter = 0;
        int skippedTimestampsCounter = 0;
        for (eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            if (tstBBB != null) {
                ++processedTimestampsCounter;
            } else {
                ++skippedTimestampsCounter;
            }
        }
        assertEquals(3, processedTimestampsCounter);
        assertEquals(0, skippedTimestampsCounter);

        assertEquals(Indication.FAILED, detailedReport.getEvidenceRecordValidationIndication(signatureEvidenceRecords.get(0).getId()));
        assertEquals(SubIndication.HASH_FAILURE, detailedReport.getEvidenceRecordValidationSubIndication(signatureEvidenceRecords.get(0).getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord evidenceRecord = detailedReport.getXmlEvidenceRecordById(signatureEvidenceRecords.get(0).getId());
        assertEquals(Indication.FAILED, evidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, evidenceRecord.getConclusion().getSubIndication());

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = evidenceRecord.getValidationProcessEvidenceRecord();
        assertEquals(Indication.FAILED, validationProcessEvidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, validationProcessEvidenceRecord.getConclusion().getSubIndication());

        int dataObjectFoundCheckCounter = 0;
        int dataObjectIntactCheckCounter = 0;
        int tstValidationValidCheckCounter = 0;
        int tstValidationInvalidCheckCounter = 0;
        int cryptoConstraintsCheckCounter = 0;
        for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
            if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectFoundCheckCounter;
            } else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++dataObjectIntactCheckCounter;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK.equals(xmlConstraint.getStatus())) {
                    ++tstValidationValidCheckCounter;
                } else if (XmlStatus.NOT_OK.equals(xmlConstraint.getStatus())) {
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getError().getKey());
                    ++tstValidationInvalidCheckCounter;
                }
            } else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++cryptoConstraintsCheckCounter;
            }
        }
        assertEquals(1, dataObjectFoundCheckCounter);
        assertEquals(1, dataObjectIntactCheckCounter);
        assertEquals(1, tstValidationValidCheckCounter);
        assertEquals(1, tstValidationInvalidCheckCounter);
        assertEquals(0, cryptoConstraintsCheckCounter);

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessArchivalData.getConclusion().getSubIndication());

        boolean evidenceRecordCheckFound = false;
        boolean ltLevelAcceptableCheckFound = false;
        boolean tstValidationCheckFound = false;
        boolean pastSignatureValidationCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IRERVPC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.ADEST_IRERVPC_ANS.getId(), xmlConstraint.getWarning().getKey());
                evidenceRecordCheckFound = true;
            } else if (MessageTag.ARCH_LTVV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ltLevelAcceptableCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                tstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
                pastSignatureValidationCheckFound = true;
            }
        }
        assertTrue(evidenceRecordCheckFound);
        assertTrue(ltLevelAcceptableCheckFound);
        assertTrue(tstValidationCheckFound);
        assertTrue(pastSignatureValidationCheckFound);
    }

    @Test
    void sigWithERLTValidationTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/sig-with-er-valid.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureTimestamps.size());
        assertEquals(Indication.INDETERMINATE, signatureTimestamps.get(0).getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureTimestamps.get(0).getSubIndication());

        List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
        assertEquals(0, signatureEvidenceRecords.size());

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(signatureTimestamps.get(0).getId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

        int processedTimestampsCounter = 0;
        int skippedTimestampsCounter = 0;
        for (eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            if (tstBBB != null) {
                assertFalse(xmlTimestamp.getType().isEvidenceRecordTimestamp());
                ++processedTimestampsCounter;
            } else {
                assertTrue(xmlTimestamp.getType().isEvidenceRecordTimestamp());
                ++skippedTimestampsCounter;
            }
        }
        assertEquals(1, processedTimestampsCounter);
        assertEquals(2, skippedTimestampsCounter);

        assertNull(detailedReport.getArchiveDataTimestampValidationIndication(signatureTimestamps.get(0).getId()));
        assertNull(detailedReport.getArchiveDataTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertNull(detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertNull(detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNull(validationProcessArchivalData);
    }

}
