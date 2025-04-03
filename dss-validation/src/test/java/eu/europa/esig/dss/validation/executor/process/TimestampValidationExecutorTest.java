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
package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTSAGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TimestampValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void timestampsSameSecond() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/timestamps_same_second.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        List<Message> warnings = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId());
        assertFalse(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.TSV_ASTPTCT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(5, timestampIds.size());
        for (String tspId : timestampIds) {
            assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(tspId));
        }

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void timestampsIncorrectOrder() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/timestamps_same_second_incorrect_order.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(5, timestampIds.size());
        for (String tspId : timestampIds) {
            assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(tspId));
        }

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void signatureWithFailedContentTstTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/sig-with-content-tst.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getUsedTimestamps().get(0).getDigestMatchers().get(0).setDataIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = detailedReport.getSignatures().get(0).getTimestamps();
        assertEquals(1, timestamps.size());

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = timestamps.get(0).getValidationProcessBasicTimestamp();
        assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());
    }

    @Test
    void signatureWithFailedContentTstFailSAVTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/sig-with-content-tst.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp xmlContentTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
        xmlContentTimestamp.getDigestMatchers().get(0).setDataIntact(false);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getSignedAttributes().setContentTimeStampMessageImprint(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_DMICTSTMCMI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

        XmlSAV sav = signatureBBB.getSAV();
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

        boolean contentTstMessageImprintCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
                assertEquals(xmlContentTimestamp.getId(), constraint.getId());
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_DMICTSTMCMI_ANS.getId(), constraint.getError().getKey());
                contentTstMessageImprintCheckFound = true;
            }
        }
        assertTrue(contentTstMessageImprintCheckFound);
    }

    @Test
    void validBLevelBestSignatureTimeTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp signatureTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        XmlTimestamp arcTst = xmlDiagnosticData.getUsedTimestamps().get(1);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(signatureTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
        assertNotEquals(arcTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
        assertNotEquals(xmlDiagnosticData.getValidationDate(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
    }

    @Test
    void validBLevelBrokenSigTstBestSignatureTimeTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp signatureTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        XmlTimestamp arcTst = xmlDiagnosticData.getUsedTimestamps().get(1);

        signatureTst.getBasicSignature().setSignatureIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertNotEquals(signatureTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
        assertEquals(arcTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
        assertNotEquals(xmlDiagnosticData.getValidationDate(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
    }

    @Test
    void validBLevelTwoBrokenTstsBestSignatureTimeTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp signatureTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        XmlTimestamp arcTst = xmlDiagnosticData.getUsedTimestamps().get(1);

        signatureTst.getBasicSignature().setSignatureIntact(false);
        arcTst.getBasicSignature().setSignatureIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertNotEquals(signatureTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
        assertNotEquals(arcTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
        assertEquals(xmlDiagnosticData.getValidationDate(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
    }

    @Test
    void tstInfoTsaFieldOrderDoesNotMatchTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/dss-2155.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        TimestampConstraints timestampConstraints = validationPolicy.getTimestampConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        timestampConstraints.setTSAGeneralNamePresent(levelConstraint);
        timestampConstraints.setTSAGeneralNameContentMatch(levelConstraint);
        timestampConstraints.setTSAGeneralNameOrderMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps =
                simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureTimestamps.size());

        eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp = signatureTimestamps.get(0);
        assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, timestamp.getSubIndication());
        assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getInfo()));
        assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getWarning()));
        assertEquals(1, timestamp.getAdESValidationDetails().getError().size());
        assertEquals(MessageTag.BBB_TAV_DTSAOM_ANS.getId(),
                timestamp.getAdESValidationDetails().getError().get(0).getKey());
    }

    @Test
    void tstInfoTsaFieldValueDoesNotMatchFailLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/dss-2155.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
        XmlTSAGeneralName tsaGeneralName = xmlTimestamp.getTSAGeneralName();
        tsaGeneralName.setContentMatch(false);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        TimestampConstraints timestampConstraints = validationPolicy.getTimestampConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        timestampConstraints.setTSAGeneralNamePresent(levelConstraint);
        timestampConstraints.setTSAGeneralNameContentMatch(levelConstraint);
        timestampConstraints.setTSAGeneralNameOrderMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps =
                simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureTimestamps.size());

        eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp = signatureTimestamps.get(0);
        assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, timestamp.getSubIndication());
        assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getInfo()));
        assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getWarning()));
        assertEquals(1, timestamp.getAdESValidationDetails().getError().size());
        assertEquals(MessageTag.BBB_TAV_DTSAVM_ANS.getId(),
                timestamp.getAdESValidationDetails().getError().get(0).getKey());
    }

    @Test
    void tstInfoTsaFieldValueNotPresentFailLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/dss-2155.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
        xmlTimestamp.setTSAGeneralName(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        TimestampConstraints timestampConstraints = validationPolicy.getTimestampConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        timestampConstraints.setTSAGeneralNamePresent(levelConstraint);
        timestampConstraints.setTSAGeneralNameContentMatch(levelConstraint);
        timestampConstraints.setTSAGeneralNameOrderMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps =
                simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureTimestamps.size());

        eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp = signatureTimestamps.get(0);
        assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, timestamp.getSubIndication());
        assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getInfo()));
        assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getWarning()));
        assertEquals(1, timestamp.getAdESValidationDetails().getError().size());
        assertEquals(MessageTag.BBB_TAV_ITSAP_ANS.getId(),
                timestamp.getAdESValidationDetails().getError().get(0).getKey());
    }

    @Test
    void tstInfoTsaFieldValueNotPresentSkipTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/dss-2155.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
        xmlTimestamp.setTSAGeneralName(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        TimestampConstraints timestampConstraints = validationPolicy.getTimestampConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        timestampConstraints.setTSAGeneralNameContentMatch(levelConstraint);
        timestampConstraints.setTSAGeneralNameOrderMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps =
                simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureTimestamps.size());

        eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp = signatureTimestamps.get(0);
        assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, timestamp.getSubIndication());
    }

    @Test
    void failTimestampDelayTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/universign.xml"));
        assertNotNull(diagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        validationPolicy.getTimestampConstraints().getTimestampDelay().setLevel(Level.FAIL);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void signBeforeBestSignatureTimeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sign_before_sig_tst.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NOT_YET_VALID, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.TSV_IBSTAIDOSC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.FAILED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.NOT_YET_VALID, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signTimeNotBeforeCertNotBeforeCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.TSV_IBSTAIDOSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.TSV_IBSTAIDOSC_ANS.getId(), constraint.getError().getKey());
                signTimeNotBeforeCertNotBeforeCheckFound = true;
            }
        }
        assertTrue(signTimeNotBeforeCertNotBeforeCheckFound);
    }

    @Test
    void signatureTimeStampPresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getUnsignedAttributes().setSignatureTimeStamp(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV sav = sigBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

        boolean tstPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_SAV_IUQPSTSP.getId().equals(constraint.getName().getKey())) {
                tstPresentCheckFound = true;
            }
        }
        assertTrue(tstPresentCheckFound);

        xmlDiagnosticData.getUsedTimestamps().get(0).setType(TimestampType.CONTENT_TIMESTAMP);

        reports = executor.execute();
        assertNotNull(reports);

        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_IUQPSTSP_ANS)));

        detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

        sav = sigBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

        tstPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (MessageTag.BBB_SAV_IUQPSTSP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_IUQPSTSP_ANS.getId(), constraint.getError().getKey());
                tstPresentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(tstPresentCheckFound);
    }

    @Test
    void validationDataTimeStampPresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getUnsignedAttributes().setValidationDataTimeStamp(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_IUQPVDTSP_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

        XmlSAV sav = sigBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

        boolean tstPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (MessageTag.BBB_SAV_IUQPVDTSP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_IUQPVDTSP_ANS.getId(), constraint.getError().getKey());
                tstPresentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(tstPresentCheckFound);

        xmlDiagnosticData.getUsedTimestamps().get(1).setType(TimestampType.VALIDATION_DATA_TIMESTAMP);

        reports = executor.execute();
        assertNotNull(reports);

        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

        sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        sav = sigBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

        tstPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_SAV_IUQPVDTSP.getId().equals(constraint.getName().getKey())) {
                tstPresentCheckFound = true;
            }
        }
        assertTrue(tstPresentCheckFound);
    }

    @Test
    void validationDataRefsOnlyTimeStampPresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getUnsignedAttributes().setValidationDataRefsOnlyTimeStamp(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_IUQPVDROTSP_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

        XmlSAV sav = sigBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

        boolean tstPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (MessageTag.BBB_SAV_IUQPVDROTSP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_IUQPVDROTSP_ANS.getId(), constraint.getError().getKey());
                tstPresentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(tstPresentCheckFound);

        xmlDiagnosticData.getUsedTimestamps().get(1).setType(TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);

        reports = executor.execute();
        assertNotNull(reports);

        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

        sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        sav = sigBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

        tstPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_SAV_IUQPVDROTSP.getId().equals(constraint.getName().getKey())) {
                tstPresentCheckFound = true;
            }
        }
        assertTrue(tstPresentCheckFound);
    }

    @Test
    void archiveTimeStampPresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getUnsignedAttributes().setArchiveTimeStamp(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV sav = sigBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

        boolean tstPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_SAV_IUQPATSP.getId().equals(constraint.getName().getKey())) {
                tstPresentCheckFound = true;
            }
        }
        assertTrue(tstPresentCheckFound);

        xmlDiagnosticData.getUsedTimestamps().get(1).setType(TimestampType.VALIDATION_DATA_TIMESTAMP);

        reports = executor.execute();
        assertNotNull(reports);

        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_IUQPATSP_ANS)));

        detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

        sav = sigBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

        tstPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (MessageTag.BBB_SAV_IUQPATSP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_IUQPATSP_ANS.getId(), constraint.getError().getKey());
                tstPresentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(tstPresentCheckFound);
    }

    @Test
    void documentTimeStampPresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pades_lta_mod_tst.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getUnsignedAttributes().setDocumentTimeStamp(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV sav = sigBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

        boolean tstPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_SAV_IDTSP.getId().equals(constraint.getName().getKey())) {
                tstPresentCheckFound = true;
            }
        }
        assertTrue(tstPresentCheckFound);

        xmlDiagnosticData.getUsedTimestamps().get(1).setType(TimestampType.VRI_TIMESTAMP);

        reports = executor.execute();
        assertNotNull(reports);

        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_IDTSP_ANS)));

        detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

        sav = sigBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

        tstPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (MessageTag.BBB_SAV_IDTSP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_IDTSP_ANS.getId(), constraint.getError().getKey());
                tstPresentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(tstPresentCheckFound);

    }

}
