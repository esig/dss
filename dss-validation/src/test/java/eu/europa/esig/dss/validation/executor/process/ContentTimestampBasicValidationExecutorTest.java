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
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContentTimestampBasicValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void contentTstValidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = signatureBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        String tstId = contentTst.getId();

        boolean contentTstValidCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_SAV_ICTVS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                                ValidationProcessUtils.getTimestampTypeMessageTag(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP),
                                tstId, ValidationProcessUtils.getFormattedDate(contentTst.getProductionTime())),
                        xmlConstraint.getAdditionalInfo());
                contentTstValidCheckFound = true;
            }
        }
        assertTrue(contentTstValidCheckFound);

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(tstId).getValidationProcessBasicTimestamp();
        assertNotNull(validationProcessTimestamp);
        assertEquals(Indication.PASSED, validationProcessTimestamp.getConclusion().getIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean ltaMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), xmlConstraint.getInfo().getKey());
                ltaMaterialPresentCheckFound = true;
            }
        }
        assertTrue(ltaMaterialPresentCheckFound);
    }

    @Test
    void contentTstInvalidNoConstraintTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getUsedTimestamps().get(0).getBasicSignature().setSignatureIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = signatureBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        String tstId = contentTst.getId();

        boolean contentTstValidCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_SAV_ICTVS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_ICTVS_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                                ValidationProcessUtils.getTimestampTypeMessageTag(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP),
                                tstId, ValidationProcessUtils.getFormattedDate(contentTst.getProductionTime())),
                        xmlConstraint.getAdditionalInfo());
                contentTstValidCheckFound = true;
            }
        }
        assertTrue(contentTstValidCheckFound);

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(tstId).getValidationProcessBasicTimestamp();
        assertNotNull(validationProcessTimestamp);
        assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean ltaMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), xmlConstraint.getInfo().getKey());
                ltaMaterialPresentCheckFound = true;
            }
        }
        assertTrue(ltaMaterialPresentCheckFound);
    }

    @Test
    void contentTstInvalidIgnoreLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getUsedTimestamps().get(0).getBasicSignature().setSignatureIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.IGNORE);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = signatureBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        String tstId = contentTst.getId();

        boolean contentTstValidCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_SAV_ICTVS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                assertNull(xmlConstraint.getAdditionalInfo());
                contentTstValidCheckFound = true;
            }
        }
        assertTrue(contentTstValidCheckFound);

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(tstId).getValidationProcessBasicTimestamp();
        assertNotNull(validationProcessTimestamp);
        assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean ltaMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), xmlConstraint.getInfo().getKey());
                ltaMaterialPresentCheckFound = true;
            }
        }
        assertTrue(ltaMaterialPresentCheckFound);
    }

    @Test
    void contentTstInvalidWarnLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getUsedTimestamps().get(0).getBasicSignature().setSignatureIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = signatureBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        String tstId = contentTst.getId();

        boolean contentTstValidCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_SAV_ICTVS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_ICTVS_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                                ValidationProcessUtils.getTimestampTypeMessageTag(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP),
                                tstId, ValidationProcessUtils.getFormattedDate(contentTst.getProductionTime())),
                        xmlConstraint.getAdditionalInfo());
                contentTstValidCheckFound = true;
            }
        }
        assertTrue(contentTstValidCheckFound);

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(tstId).getValidationProcessBasicTimestamp();
        assertNotNull(validationProcessTimestamp);
        assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean ltaMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), xmlConstraint.getInfo().getKey());
                ltaMaterialPresentCheckFound = true;
            }
        }
        assertTrue(ltaMaterialPresentCheckFound);
    }

    @Test
    void contentTstInvalidFailLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getUsedTimestamps().get(0).getBasicSignature().setSignatureIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlSAV xmlSAV = signatureBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        String tstId = contentTst.getId();

        boolean contentTstValidCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_SAV_ICTVS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_ICTVS_ANS.getId(), xmlConstraint.getError().getKey());
                assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                                ValidationProcessUtils.getTimestampTypeMessageTag(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP),
                                tstId, ValidationProcessUtils.getFormattedDate(contentTst.getProductionTime())),
                        xmlConstraint.getAdditionalInfo());
                contentTstValidCheckFound = true;
            }
        }
        assertTrue(contentTstValidCheckFound);

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(tstId).getValidationProcessBasicTimestamp();
        assertNotNull(validationProcessTimestamp);
        assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, validationProcessArchivalData.getConclusion().getSubIndication());

        boolean ltaMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), xmlConstraint.getError().getKey());
                ltaMaterialPresentCheckFound = true;
            }
        }
        assertTrue(ltaMaterialPresentCheckFound);
    }

    @Test
    void contentTstValidLtaEnabledTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pastSigValidation.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = signatureBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        String tstId = contentTst.getId();

        boolean contentTstValidCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_SAV_ICTVS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                                ValidationProcessUtils.getTimestampTypeMessageTag(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP),
                                tstId, ValidationProcessUtils.getFormattedDate(contentTst.getProductionTime())),
                        xmlConstraint.getAdditionalInfo());
                contentTstValidCheckFound = true;
            }
        }
        assertTrue(contentTstValidCheckFound);

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(tstId).getValidationProcessBasicTimestamp();
        assertNotNull(validationProcessTimestamp);
        assertEquals(Indication.PASSED, validationProcessTimestamp.getConclusion().getIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean ltaMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ltaMaterialPresentCheckFound = true;
            }
        }
        assertTrue(ltaMaterialPresentCheckFound);
    }

    @Test
    void contentTstInvalidWarnLevelLtaEnabledTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pastSigValidation.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getUsedTimestamps().get(0).getBasicSignature().setSignatureIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = signatureBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        String tstId = contentTst.getId();

        boolean contentTstValidCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_SAV_ICTVS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_ICTVS_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                                ValidationProcessUtils.getTimestampTypeMessageTag(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP),
                                tstId, ValidationProcessUtils.getFormattedDate(contentTst.getProductionTime())),
                        xmlConstraint.getAdditionalInfo());
                contentTstValidCheckFound = true;
            }
        }
        assertTrue(contentTstValidCheckFound);

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(tstId).getValidationProcessBasicTimestamp();
        assertNotNull(validationProcessTimestamp);
        assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        contentTstValidCheckFound = false;
        boolean ltaMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ltaMaterialPresentCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.WARNING.equals(xmlConstraint.getStatus())) {
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getWarning().getKey());
                    assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                    contentTstValidCheckFound = true;
                }
            }
        }
        assertTrue(contentTstValidCheckFound);
        assertTrue(ltaMaterialPresentCheckFound);
    }

    @Test
    void contentTstInvalidFailLevelLtaEnabledTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pastSigValidation.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getUsedTimestamps().get(0).getBasicSignature().setSignatureIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = signatureBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        String tstId = contentTst.getId();

        boolean contentTstValidCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_SAV_ICTVS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_ICTVS_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                                ValidationProcessUtils.getTimestampTypeMessageTag(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP),
                                tstId, ValidationProcessUtils.getFormattedDate(contentTst.getProductionTime())),
                        xmlConstraint.getAdditionalInfo());
                contentTstValidCheckFound = true;
            }
        }
        assertTrue(contentTstValidCheckFound);

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(tstId).getValidationProcessBasicTimestamp();
        assertNotNull(validationProcessTimestamp);
        assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.FAILED, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessArchivalData.getConclusion().getSubIndication());

        contentTstValidCheckFound = false;
        boolean ltaMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ltaMaterialPresentCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.NOT_OK.equals(xmlConstraint.getStatus())) {
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getError().getKey());
                    assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                    contentTstValidCheckFound = true;
                }
            }
        }
        assertTrue(contentTstValidCheckFound);
        assertTrue(ltaMaterialPresentCheckFound);
    }

    @Test
    void contentTstExpiredWithPOEValidLtaEnabledTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pastSigValidation_diff_cnt_tst_issuer.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = signatureBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        String tstId = contentTst.getId();

        boolean contentTstValidCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_SAV_ICTVS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_ICTVS_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                                ValidationProcessUtils.getTimestampTypeMessageTag(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP),
                                tstId, ValidationProcessUtils.getFormattedDate(contentTst.getProductionTime())),
                        xmlConstraint.getAdditionalInfo());
                contentTstValidCheckFound = true;
            }
        }
        assertTrue(contentTstValidCheckFound);

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(tstId).getValidationProcessBasicTimestamp();
        assertNotNull(validationProcessTimestamp);
        assertEquals(Indication.INDETERMINATE, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        contentTstValidCheckFound = false;
        boolean ltaMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ltaMaterialPresentCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                if (xmlDiagnosticData.getUsedTimestamps().get(0).getId().equals(xmlConstraint.getId())) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    contentTstValidCheckFound = true;
                }
            }
        }
        assertTrue(contentTstValidCheckFound);
        assertTrue(ltaMaterialPresentCheckFound);
    }

    @Test
    void contentTstExpiredNoPOEValidLtaEnabledTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pastSigValidation_diff_cnt_tst_issuer.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate cntTstIssuerCert = xmlDiagnosticData.getUsedTimestamps().get(0).getSigningCertificate().getCertificate();
        cntTstIssuerCert.setNotAfter(DSSUtils.parseRFCDate("2018-12-06T13:04:10Z"));

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = signatureBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
        String tstId = contentTst.getId();

        boolean contentTstValidCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_SAV_ICTVS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_ICTVS_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                                ValidationProcessUtils.getTimestampTypeMessageTag(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP),
                                tstId, ValidationProcessUtils.getFormattedDate(contentTst.getProductionTime())),
                        xmlConstraint.getAdditionalInfo());
                contentTstValidCheckFound = true;
            }
        }
        assertTrue(contentTstValidCheckFound);

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(tstId).getValidationProcessBasicTimestamp();
        assertNotNull(validationProcessTimestamp);
        assertEquals(Indication.INDETERMINATE, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessArchivalData.getConclusion().getSubIndication());

        contentTstValidCheckFound = false;
        boolean ltaMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ltaMaterialPresentCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.NOT_OK.equals(xmlConstraint.getStatus())) {
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getError().getKey());
                    assertEquals(xmlDiagnosticData.getUsedTimestamps().get(0).getId(), xmlConstraint.getId());
                    contentTstValidCheckFound = true;
                }
            }
        }
        assertTrue(contentTstValidCheckFound);
        assertTrue(ltaMaterialPresentCheckFound);
    }

}
