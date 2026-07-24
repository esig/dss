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
package eu.europa.esig.dss.validation.executor;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlAOV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEAA;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEAA;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAAPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAARevocationToken;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.eaa.AttestationProcessExecutor;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttestationValidationProcessExecutorTest extends AbstractTestValidationExecutor {

    private static final String EAA_POLICY_LOCATION = "/policy/eaa-constraint.xml";

    private static I18nProvider i18nProvider;

    @BeforeAll
    static void init() {
        i18nProvider = new I18nProvider(Locale.getDefault());
    }

    @Test
    void validTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                sigValidationConclusiveCheckFound = true;
            } else if (MessageTag.EAA_KBRC.getId().equals(xmlConstraint.getName().getKey())) {
                kbSigValidationConclusiveCheckFound = true;
            } else if (MessageTag.BSV_ICVRC.getId().equals(xmlConstraint.getName().getKey())) {
                cvCheckFound = true;
            } else if (MessageTag.BSV_IEAAAVRC.getId().equals(xmlConstraint.getName().getKey())) {
                savCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);
        assertTrue(kbSigValidationConclusiveCheckFound);
        assertTrue(cvCheckFound);
        assertTrue(savCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        boolean sigPresentCheckFound = false;
        boolean disclosuresPresentCheckFound = false;
        boolean kbSigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                sigPresentCheckFound = true;
            } else if (MessageTag.EAA_DPEAAP.getId().equals(xmlConstraint.getName().getKey())) {
                disclosuresPresentCheckFound = true;
            } else if (MessageTag.EAA_KBSP.getId().equals(xmlConstraint.getName().getKey())) {
                kbSigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);
        assertTrue(disclosuresPresentCheckFound);
        assertTrue(kbSigPresentCheckFound);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);

        int disclosureFoundCounter = 0;
        int disclosureIntactCounter = 0;
        for (XmlConstraint xmlConstraint : xmlCV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_CV_EAA_SDCBF.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureFoundCounter;
            } else if (MessageTag.BBB_CV_EAA_SDCBI.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureIntactCounter;
            }
        }
        assertEquals(10, disclosureFoundCounter);
        assertEquals(10, disclosureIntactCounter);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);

        assertNull(eaaBBB.getISC());
        assertNull(eaaBBB.getVCI());
        assertNull(eaaBBB.getXCV());

        checkReports(reports);
    }

    @Test
    void validWithOrphanDisclosuresTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getEAAs().get(0).getDigestMatchers();

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.EAA_ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM);
        xmlDigestMatcher.setDataFound(false);
        xmlDigestMatcher.setDataIntact(false);
        digestMatchers.add(xmlDigestMatcher);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                sigValidationConclusiveCheckFound = true;
            } else if (MessageTag.EAA_KBRC.getId().equals(xmlConstraint.getName().getKey())) {
                kbSigValidationConclusiveCheckFound = true;
            } else if (MessageTag.BSV_ICVRC.getId().equals(xmlConstraint.getName().getKey())) {
                cvCheckFound = true;
            } else if (MessageTag.BSV_IEAAAVRC.getId().equals(xmlConstraint.getName().getKey())) {
                savCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);
        assertTrue(kbSigValidationConclusiveCheckFound);
        assertTrue(cvCheckFound);
        assertTrue(savCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        boolean sigPresentCheckFound = false;
        boolean disclosuresPresentCheckFound = false;
        boolean kbSigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                sigPresentCheckFound = true;
            } else if (MessageTag.EAA_DPEAAP.getId().equals(xmlConstraint.getName().getKey())) {
                disclosuresPresentCheckFound = true;
            } else if (MessageTag.EAA_KBSP.getId().equals(xmlConstraint.getName().getKey())) {
                kbSigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);
        assertTrue(disclosuresPresentCheckFound);
        assertTrue(kbSigPresentCheckFound);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);

        int disclosureFoundCounter = 0;
        int disclosureIntactCounter = 0;
        for (XmlConstraint xmlConstraint : xmlCV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_CV_EAA_SDCBF.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureFoundCounter;
            } else if (MessageTag.BBB_CV_EAA_SDCBI.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureIntactCounter;
            }
        }
        assertEquals(10, disclosureFoundCounter);
        assertEquals(10, disclosureIntactCounter);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);

        checkReports(reports);
    }

    @Test
    void disclosureNotIntactTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getEAAs().get(0).getDigestMatchers();
        digestMatchers.get(0).setDataIntact(false);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.BBB_CV_EAA_SDCBI_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.HASH_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.FAILED, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                sigValidationConclusiveCheckFound = true;
            } else if (MessageTag.EAA_KBRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kbSigValidationConclusiveCheckFound = true;
            } else if (MessageTag.BSV_ICVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BSV_ICVRC_ANS.getId(), xmlConstraint.getError().getKey());
                cvCheckFound = true;
            } else if (MessageTag.BSV_IEAAAVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                savCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);
        assertTrue(kbSigValidationConclusiveCheckFound);
        assertTrue(cvCheckFound);
        assertFalse(savCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        boolean sigPresentCheckFound = false;
        boolean disclosuresPresentCheckFound = false;
        boolean kbSigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                sigPresentCheckFound = true;
            } else if (MessageTag.EAA_DPEAAP.getId().equals(xmlConstraint.getName().getKey())) {
                disclosuresPresentCheckFound = true;
            } else if (MessageTag.EAA_KBSP.getId().equals(xmlConstraint.getName().getKey())) {
                kbSigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);
        assertTrue(disclosuresPresentCheckFound);
        assertTrue(kbSigPresentCheckFound);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.FAILED, xmlCV.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, xmlCV.getConclusion().getSubIndication());

        int disclosureFoundCounter = 0;
        int disclosureIntactCounter = 0;
        for (XmlConstraint xmlConstraint : xmlCV.getConstraint()) {
            if (MessageTag.BBB_CV_EAA_SDCBF.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++disclosureFoundCounter;
            } else if (MessageTag.BBB_CV_EAA_SDCBI.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_CV_EAA_SDCBI_ANS.getId(), xmlConstraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, digestMatchers.get(0).getDisclosableClaim().getName()), xmlConstraint.getAdditionalInfo());
                ++disclosureIntactCounter;
            }
        }
        assertEquals(1, disclosureFoundCounter);
        assertEquals(1, disclosureIntactCounter);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void noDisclosuresWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa_no_disclosures.xml"));
        assertNotNull(diagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getEAAConstraints().setDisclosurePresent(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_DPEAAP_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                sigValidationConclusiveCheckFound = true;
            } else if (MessageTag.EAA_KBRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kbSigValidationConclusiveCheckFound = true;
            } else if (MessageTag.BSV_ICVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                cvCheckFound = true;
            } else if (MessageTag.BSV_IEAAAVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                savCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);
        assertTrue(kbSigValidationConclusiveCheckFound);
        assertTrue(cvCheckFound);
        assertTrue(savCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        boolean sigPresentCheckFound = false;
        boolean disclosuresPresentCheckFound = false;
        boolean kbSigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                sigPresentCheckFound = true;
            } else if (MessageTag.EAA_DPEAAP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_DPEAAP_ANS.getId(), xmlConstraint.getWarning().getKey());
                disclosuresPresentCheckFound = true;
            } else if (MessageTag.EAA_KBSP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kbSigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);
        assertTrue(disclosuresPresentCheckFound);
        assertTrue(kbSigPresentCheckFound);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        int disclosureFoundCounter = 0;
        int disclosureIntactCounter = 0;
        for (XmlConstraint xmlConstraint : xmlCV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_CV_EAA_SDCBF.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureFoundCounter;
            } else if (MessageTag.BBB_CV_EAA_SDCBI.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureIntactCounter;
            }
        }
        assertEquals(0, disclosureFoundCounter);
        assertEquals(0, disclosureIntactCounter);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void noDisclosuresFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa_no_disclosures.xml"));
        assertNotNull(diagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEAAConstraints().setDisclosurePresent(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));

        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_DPEAAP_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.FAILED, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BSV_IFCRC_ANS.getId(), xmlConstraint.getError().getKey());
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                sigValidationConclusiveCheckFound = true;
            } else if (MessageTag.EAA_KBRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kbSigValidationConclusiveCheckFound = true;
            } else if (MessageTag.BSV_ICVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                cvCheckFound = true;
            } else if (MessageTag.BSV_IEAAAVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                savCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertFalse(sigValidationConclusiveCheckFound);
        assertFalse(kbSigValidationConclusiveCheckFound);
        assertFalse(cvCheckFound);
        assertFalse(savCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.FAILED, xmlFC.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, xmlFC.getConclusion().getSubIndication());

        boolean sigPresentCheckFound = false;
        boolean disclosuresPresentCheckFound = false;
        boolean kbSigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                sigPresentCheckFound = true;
            } else if (MessageTag.EAA_DPEAAP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_DPEAAP_ANS.getId(), xmlConstraint.getError().getKey());
                disclosuresPresentCheckFound = true;
            } else if (MessageTag.EAA_KBSP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kbSigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);
        assertTrue(disclosuresPresentCheckFound);
        assertFalse(kbSigPresentCheckFound);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        int disclosureFoundCounter = 0;
        int disclosureIntactCounter = 0;
        for (XmlConstraint xmlConstraint : xmlCV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_CV_EAA_SDCBF.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureFoundCounter;
            } else if (MessageTag.BBB_CV_EAA_SDCBI.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureIntactCounter;
            }
        }
        assertEquals(0, disclosureFoundCounter);
        assertEquals(0, disclosureIntactCounter);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void sigInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add(SignatureLevel.CB_AdES_BASELINE_B.toString());
        constraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().setAcceptableFormats(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.ADEST_IBSVPSC_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        List<XmlSignature> eaaSignatures = simpleReport.getEAASignatures(simpleReport.getFirstEAAId());
        assertEquals(1, eaaSignatures.size());
        XmlSignature eaaSignature = eaaSignatures.get(0);

        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(eaaSignature.getId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(eaaSignature.getId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(eaaSignature.getId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(eaaSignature.getId()), i18nProvider.getMessage(MessageTag.BBB_FC_IEFF_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(eaaSignature.getId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(eaaSignature.getId())));

        XmlSignature keyBindingSignature = simpleReport.getEAAKeyBindingSignature(simpleReport.getFirstEAAId());
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(keyBindingSignature.getId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(keyBindingSignature.getId())));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(keyBindingSignature.getId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(keyBindingSignature.getId()), i18nProvider.getMessage(MessageTag.BBB_ICS_ISCI_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(keyBindingSignature.getId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.FAILED, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPSC_ANS.getId(), xmlConstraint.getError().getKey());
                sigValidationConclusiveCheckFound = true;
            } else if (MessageTag.EAA_KBRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kbSigValidationConclusiveCheckFound = true;
            } else if (MessageTag.BSV_ICVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                cvCheckFound = true;
            } else if (MessageTag.BSV_IEAAAVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                savCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);
        assertFalse(kbSigValidationConclusiveCheckFound);
        assertFalse(cvCheckFound);
        assertFalse(savCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        boolean sigPresentCheckFound = false;
        boolean disclosuresPresentCheckFound = false;
        boolean kbSigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                sigPresentCheckFound = true;
            } else if (MessageTag.EAA_DPEAAP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                disclosuresPresentCheckFound = true;
            } else if (MessageTag.EAA_KBSP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kbSigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);
        assertTrue(disclosuresPresentCheckFound);
        assertTrue(kbSigPresentCheckFound);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        int disclosureFoundCounter = 0;
        int disclosureIntactCounter = 0;
        for (XmlConstraint xmlConstraint : xmlCV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_CV_EAA_SDCBF.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureFoundCounter;
            } else if (MessageTag.BBB_CV_EAA_SDCBI.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureIntactCounter;
            }
        }
        assertEquals(10, disclosureFoundCounter);
        assertEquals(10, disclosureIntactCounter);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void kbSigInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add(SignatureLevel.CB_AdES_BASELINE_B.toString());
        constraint.setLevel(Level.FAIL);
        validationPolicy.getKeyBindingSignatureConstraints().setAcceptableFormats(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_KBRC_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        List<XmlSignature> eaaSignatures = simpleReport.getEAASignatures(simpleReport.getFirstEAAId());
        assertEquals(1, eaaSignatures.size());
        XmlSignature eaaSignature = eaaSignatures.get(0);

        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(eaaSignature.getId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(eaaSignature.getId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(eaaSignature.getId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(eaaSignature.getId())));

        XmlSignature keyBindingSignature = simpleReport.getEAAKeyBindingSignature(simpleReport.getFirstEAAId());
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(keyBindingSignature.getId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(keyBindingSignature.getId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(keyBindingSignature.getId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(keyBindingSignature.getId()), i18nProvider.getMessage(MessageTag.BBB_FC_IEFF_ANS)));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(keyBindingSignature.getId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(keyBindingSignature.getId()), i18nProvider.getMessage(MessageTag.BBB_ICS_ISCI_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(keyBindingSignature.getId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.FAILED, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                sigValidationConclusiveCheckFound = true;
            } else if (MessageTag.EAA_KBRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_KBRC_ANS.getId(), xmlConstraint.getError().getKey());
                kbSigValidationConclusiveCheckFound = true;
            } else if (MessageTag.BSV_ICVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                cvCheckFound = true;
            } else if (MessageTag.BSV_IEAAAVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                savCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);
        assertTrue(kbSigValidationConclusiveCheckFound);
        assertFalse(cvCheckFound);
        assertFalse(savCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        boolean sigPresentCheckFound = false;
        boolean disclosuresPresentCheckFound = false;
        boolean kbSigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                sigPresentCheckFound = true;
            } else if (MessageTag.EAA_DPEAAP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                disclosuresPresentCheckFound = true;
            } else if (MessageTag.EAA_KBSP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kbSigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);
        assertTrue(disclosuresPresentCheckFound);
        assertTrue(kbSigPresentCheckFound);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        int disclosureFoundCounter = 0;
        int disclosureIntactCounter = 0;
        for (XmlConstraint xmlConstraint : xmlCV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_CV_EAA_SDCBF.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureFoundCounter;
            } else if (MessageTag.BBB_CV_EAA_SDCBI.getId().equals(xmlConstraint.getName().getKey())) {
                ++disclosureIntactCounter;
            }
        }
        assertEquals(10, disclosureFoundCounter);
        assertEquals(10, disclosureIntactCounter);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void technicalPeriodExpiredFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(diagnosticData.getValidationDate());
        calendar.set(Calendar.MINUTE, -1);

        XmlEAAPayload eaaPayload = diagnosticData.getEAAs().get(0).getEAAPayload();
        XmlClaim expirationClaim = new XmlClaim();
        expirationClaim.setDateTime(calendar.getTime());
        eaaPayload.setExpiration(expirationClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEAAConstraints().setEAANotExpired(levelConstraint);
        validationPolicy.getEAAConstraints().setEAAAdministrativePeriodNotExpired(levelConstraint);

        LevelConstraint etsiConstraint = new LevelConstraint();
        etsiConstraint.setLevel(Level.WARN);
        validationPolicy.getEAAConstraints().setETSI194721Conformance(etsiConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));

        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_VT_ITVR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_ETSI194721_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessEAA.getConclusion().getSubIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                sigValidationConclusiveCheckFound = true;
            } else if (MessageTag.EAA_KBRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kbSigValidationConclusiveCheckFound = true;
            } else if (MessageTag.BSV_ICVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                cvCheckFound = true;
            } else if (MessageTag.BSV_IEAAAVRC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BSV_IEAAAVRC_ANS.getId(), xmlConstraint.getError().getKey());
                savCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);
        assertTrue(kbSigValidationConclusiveCheckFound);
        assertTrue(cvCheckFound);
        assertTrue(savCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xmlSAV.getConclusion().getSubIndication());

        boolean etsiConformanceCheckFound = false;
        boolean technicalValidityNotBeforeCheckFound = false;
        boolean technicalValidityExpirationCheckFound = false;
        boolean technicalValidityPeriodCheckFound = false;
        boolean administrativeValidityNotBeforeCheckFound = false;
        boolean administrativeValidityExpirationCheckFound = false;
        boolean administrativeValidityPeriodCheckFound = false;

        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_ETSI194721.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_ETSI194721_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_NOW_AFTER_EXP,
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getExpiration().getDateTime())), xmlConstraint.getAdditionalInfo());
                etsiConformanceCheckFound = true;
            } else if (MessageTag.EAA_NBF_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityNotBeforeCheckFound = true;
            } else if (MessageTag.EAA_EXP_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityExpirationCheckFound = true;
            } else if (MessageTag.EAA_VT_ITVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_VT_ITVR_ANS.getId(), xmlConstraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_VT_ITVR_VALIDITY,
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getNotBefore().getDateTime()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getExpiration().getDateTime())), xmlConstraint.getAdditionalInfo());
                technicalValidityPeriodCheckFound = true;
            } else if (MessageTag.EAA_AID_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityNotBeforeCheckFound = true;
            } else if (MessageTag.EAA_AED_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityExpirationCheckFound = true;
            } else if (MessageTag.EAA_VT_IAVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityPeriodCheckFound = true;
            }
        }
        assertTrue(etsiConformanceCheckFound);
        assertTrue(technicalValidityNotBeforeCheckFound);
        assertTrue(technicalValidityExpirationCheckFound);
        assertTrue(technicalValidityPeriodCheckFound);
        assertFalse(administrativeValidityNotBeforeCheckFound);
        assertFalse(administrativeValidityExpirationCheckFound);
        assertFalse(administrativeValidityPeriodCheckFound);

        checkReports(reports);
    }

    @Test
    void technicalPeriodExpiredWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(diagnosticData.getValidationDate());
        calendar.set(Calendar.MINUTE, -1);

        XmlEAAPayload eaaPayload = diagnosticData.getEAAs().get(0).getEAAPayload();
        XmlClaim expirationClaim = new XmlClaim();
        expirationClaim.setDateTime(calendar.getTime());
        eaaPayload.setExpiration(expirationClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getEAAConstraints().setEAANotExpired(levelConstraint);
        validationPolicy.getEAAConstraints().setEAAAdministrativePeriodNotExpired(levelConstraint);

        LevelConstraint etsiConstraint = new LevelConstraint();
        etsiConstraint.setLevel(Level.WARN);
        validationPolicy.getEAAConstraints().setETSI194721Conformance(etsiConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));

        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_VT_ITVR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_ETSI194721_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean etsiConformanceCheckFound = false;
        boolean technicalValidityNotBeforeCheckFound = false;
        boolean technicalValidityExpirationCheckFound = false;
        boolean technicalValidityPeriodCheckFound = false;
        boolean administrativeValidityNotBeforeCheckFound = false;
        boolean administrativeValidityExpirationCheckFound = false;
        boolean administrativeValidityPeriodCheckFound = false;

        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_ETSI194721.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_ETSI194721_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_NOW_AFTER_EXP,
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getExpiration().getDateTime())), xmlConstraint.getAdditionalInfo());
                etsiConformanceCheckFound = true;
            } else if (MessageTag.EAA_NBF_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityNotBeforeCheckFound = true;
            } else if (MessageTag.EAA_EXP_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityExpirationCheckFound = true;
            } else if (MessageTag.EAA_VT_ITVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_VT_ITVR_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_VT_ITVR_VALIDITY,
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getNotBefore().getDateTime()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getExpiration().getDateTime())), xmlConstraint.getAdditionalInfo());
                technicalValidityPeriodCheckFound = true;
            } else if (MessageTag.EAA_AID_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityNotBeforeCheckFound = true;
            } else if (MessageTag.EAA_AED_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityExpirationCheckFound = true;
            } else if (MessageTag.EAA_VT_IAVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityPeriodCheckFound = true;
            }
        }
        assertTrue(etsiConformanceCheckFound);
        assertTrue(technicalValidityNotBeforeCheckFound);
        assertTrue(technicalValidityExpirationCheckFound);
        assertTrue(technicalValidityPeriodCheckFound);
        assertFalse(administrativeValidityNotBeforeCheckFound);
        assertFalse(administrativeValidityExpirationCheckFound);
        assertFalse(administrativeValidityPeriodCheckFound);

        checkReports(reports);
    }

    @Test
    void technicalPeriodExpiredWarnEtsiFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(diagnosticData.getValidationDate());
        calendar.set(Calendar.MINUTE, -1);

        XmlEAAPayload eaaPayload = diagnosticData.getEAAs().get(0).getEAAPayload();
        XmlClaim expirationClaim = new XmlClaim();
        expirationClaim.setDateTime(calendar.getTime());
        eaaPayload.setExpiration(expirationClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getEAAConstraints().setEAANotExpired(levelConstraint);
        validationPolicy.getEAAConstraints().setEAAAdministrativePeriodNotExpired(levelConstraint);

        LevelConstraint etsiConstraint = new LevelConstraint();
        etsiConstraint.setLevel(Level.FAIL);
        validationPolicy.getEAAConstraints().setETSI194721Conformance(etsiConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));

        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_ETSI194721_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean etsiConformanceCheckFound = false;
        boolean technicalValidityNotBeforeCheckFound = false;
        boolean technicalValidityExpirationCheckFound = false;
        boolean technicalValidityPeriodCheckFound = false;
        boolean administrativeValidityNotBeforeCheckFound = false;
        boolean administrativeValidityExpirationCheckFound = false;
        boolean administrativeValidityPeriodCheckFound = false;

        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_ETSI194721.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_ETSI194721_ANS.getId(), xmlConstraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_NOW_AFTER_EXP,
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getExpiration().getDateTime())), xmlConstraint.getAdditionalInfo());
                etsiConformanceCheckFound = true;
            } else if (MessageTag.EAA_NBF_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityNotBeforeCheckFound = true;
            } else if (MessageTag.EAA_EXP_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityExpirationCheckFound = true;
            } else if (MessageTag.EAA_VT_ITVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityPeriodCheckFound = true;
            } else if (MessageTag.EAA_AID_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityNotBeforeCheckFound = true;
            } else if (MessageTag.EAA_AED_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityExpirationCheckFound = true;
            } else if (MessageTag.EAA_VT_IAVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityPeriodCheckFound = true;
            }
        }
        assertTrue(etsiConformanceCheckFound);
        assertFalse(technicalValidityNotBeforeCheckFound);
        assertFalse(technicalValidityExpirationCheckFound);
        assertFalse(technicalValidityPeriodCheckFound);
        assertFalse(administrativeValidityNotBeforeCheckFound);
        assertFalse(administrativeValidityExpirationCheckFound);
        assertFalse(administrativeValidityPeriodCheckFound);

        checkReports(reports);
    }

    @Test
    void administrativePeriodExpiredFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(diagnosticData.getValidationDate());
        calendar.set(Calendar.MINUTE, -1);

        XmlEAAPayload eaaPayload = diagnosticData.getEAAs().get(0).getEAAPayload();
        eaaPayload.setAdministrativeIssuanceDate(eaaPayload.getNotBefore());

        XmlClaim expirationClaim = new XmlClaim();
        expirationClaim.setDateTime(calendar.getTime());
        eaaPayload.setAdministrativeExpirationDate(expirationClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEAAConstraints().setEAANotExpired(levelConstraint);
        validationPolicy.getEAAConstraints().setEAAAdministrativePeriodNotExpired(levelConstraint);

        LevelConstraint etsiConstraint = new LevelConstraint();
        etsiConstraint.setLevel(Level.WARN);
        validationPolicy.getEAAConstraints().setETSI194721Conformance(etsiConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));

        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_VT_IAVR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_ETSI194721_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xmlSAV.getConclusion().getSubIndication());

        boolean etsiConformanceCheckFound = false;
        boolean technicalValidityNotBeforeCheckFound = false;
        boolean technicalValidityExpirationCheckFound = false;
        boolean technicalValidityPeriodCheckFound = false;
        boolean administrativeValidityNotBeforeCheckFound = false;
        boolean administrativeValidityExpirationCheckFound = false;
        boolean administrativeValidityPeriodCheckFound = false;

        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_ETSI194721.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_ETSI194721_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_NOW_AFTER_ADE,
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getAdministrativeExpirationDate().getDateTime())), xmlConstraint.getAdditionalInfo());
                etsiConformanceCheckFound = true;
            } else if (MessageTag.EAA_NBF_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityNotBeforeCheckFound = true;
            } else if (MessageTag.EAA_EXP_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityExpirationCheckFound = true;
            } else if (MessageTag.EAA_VT_ITVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityPeriodCheckFound = true;
            } else if (MessageTag.EAA_AID_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityNotBeforeCheckFound = true;
            } else if (MessageTag.EAA_AED_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityExpirationCheckFound = true;
            } else if (MessageTag.EAA_VT_IAVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_VT_IAVR_ANS.getId(), xmlConstraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_VT_IAVR_VALIDITY,
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getAdministrativeIssuanceDate().getDateTime()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getAdministrativeExpirationDate().getDateTime())), xmlConstraint.getAdditionalInfo());
                administrativeValidityPeriodCheckFound = true;
            }
        }
        assertTrue(etsiConformanceCheckFound);
        assertTrue(technicalValidityNotBeforeCheckFound);
        assertTrue(technicalValidityExpirationCheckFound);
        assertTrue(technicalValidityPeriodCheckFound);
        assertFalse(administrativeValidityNotBeforeCheckFound);
        assertFalse(administrativeValidityExpirationCheckFound);
        assertTrue(administrativeValidityPeriodCheckFound);

        checkReports(reports);
    }

    @Test
    void administrativePeriodExpiredWarnAllChecksPresentTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(diagnosticData.getValidationDate());
        calendar.set(Calendar.MINUTE, -1);

        XmlEAAPayload eaaPayload = diagnosticData.getEAAs().get(0).getEAAPayload();
        eaaPayload.setAdministrativeIssuanceDate(eaaPayload.getNotBefore());

        XmlClaim expirationClaim = new XmlClaim();
        expirationClaim.setDateTime(calendar.getTime());
        eaaPayload.setAdministrativeExpirationDate(expirationClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getEAAConstraints().setEAANotExpired(levelConstraint);
        validationPolicy.getEAAConstraints().setEAAAdministrativeIssuanceDatePresent(levelConstraint);
        validationPolicy.getEAAConstraints().setEAAAdministrativeExpirationDatePresent(levelConstraint);
        validationPolicy.getEAAConstraints().setEAAAdministrativePeriodNotExpired(levelConstraint);

        LevelConstraint etsiConstraint = new LevelConstraint();
        etsiConstraint.setLevel(Level.WARN);
        validationPolicy.getEAAConstraints().setETSI194721Conformance(etsiConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));

        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_VT_IAVR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_ETSI194721_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean etsiConformanceCheckFound = false;
        boolean technicalValidityNotBeforeCheckFound = false;
        boolean technicalValidityExpirationCheckFound = false;
        boolean technicalValidityPeriodCheckFound = false;
        boolean administrativeValidityNotBeforeCheckFound = false;
        boolean administrativeValidityExpirationCheckFound = false;
        boolean administrativeValidityPeriodCheckFound = false;

        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_ETSI194721.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_ETSI194721_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_NOW_AFTER_ADE,
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getAdministrativeExpirationDate().getDateTime())), xmlConstraint.getAdditionalInfo());
                etsiConformanceCheckFound = true;
            } else if (MessageTag.EAA_NBF_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityNotBeforeCheckFound = true;
            } else if (MessageTag.EAA_EXP_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityExpirationCheckFound = true;
            } else if (MessageTag.EAA_VT_ITVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                technicalValidityPeriodCheckFound = true;
            } else if (MessageTag.EAA_AID_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityNotBeforeCheckFound = true;
            } else if (MessageTag.EAA_AED_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                administrativeValidityExpirationCheckFound = true;
            } else if (MessageTag.EAA_VT_IAVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_VT_IAVR_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_VT_IAVR_VALIDITY,
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getAdministrativeIssuanceDate().getDateTime()),
                        ValidationProcessUtils.getFormattedDate(eaaPayload.getAdministrativeExpirationDate().getDateTime())), xmlConstraint.getAdditionalInfo());
                administrativeValidityPeriodCheckFound = true;
            }
        }
        assertTrue(etsiConformanceCheckFound);
        assertTrue(technicalValidityNotBeforeCheckFound);
        assertTrue(technicalValidityExpirationCheckFound);
        assertTrue(technicalValidityPeriodCheckFound);
        assertTrue(administrativeValidityNotBeforeCheckFound);
        assertTrue(administrativeValidityExpirationCheckFound);
        assertTrue(administrativeValidityPeriodCheckFound);

        checkReports(reports);
    }

    @Test
    void claimsValidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        DiagnosticData diagnosticData = new DiagnosticData(xmlDiagnosticData);
        AttestationWrapper attestationWrapper = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());

        MultiValuesConstraint claims = new MultiValuesConstraint();
        claims.setLevel(Level.FAIL);
        claims.getId().add("given_name");
        claims.getId().add("family_name");
        claims.getId().add("birthdate");
        validationPolicy.getEAAConstraints().setEAAClaims(claims);

        MultiValuesConstraint supportedClaims = new MultiValuesConstraint();
        supportedClaims.setLevel(Level.FAIL);
        supportedClaims.getId().addAll(attestationWrapper.getAllEAAPayloadClaimNames());
        validationPolicy.getEAAConstraints().setEAASupportedClaims(supportedClaims);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean claimsCheckFound = false;
        boolean supportedClaimsCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_CLAIMS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                claimsCheckFound = true;
            } else if (MessageTag.EAA_SUPPORTED_CLAIMS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                supportedClaimsCheckFound = true;
            }
        }
        assertTrue(claimsCheckFound);
        assertTrue(supportedClaimsCheckFound);

        checkReports(reports);
    }

    @Test
    void claimsNotPresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        DiagnosticData diagnosticData = new DiagnosticData(xmlDiagnosticData);
        AttestationWrapper attestationWrapper = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());

        MultiValuesConstraint claims = new MultiValuesConstraint();
        claims.setLevel(Level.FAIL);
        claims.getId().add("given_name");
        claims.getId().add("family_name");
        claims.getId().add("middle_name");
        claims.getId().add("birthdate");
        validationPolicy.getEAAConstraints().setEAAClaims(claims);

        MultiValuesConstraint supportedClaims = new MultiValuesConstraint();
        supportedClaims.setLevel(Level.FAIL);
        supportedClaims.getId().addAll(attestationWrapper.getAllEAAPayloadClaimNames());
        validationPolicy.getEAAConstraints().setEAASupportedClaims(supportedClaims);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_CLAIMS_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean claimsCheckFound = false;
        boolean supportedClaimsCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_CLAIMS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_CLAIMS_ANS.getId(), xmlConstraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_CLAIMS_INFO, "middle_name"), xmlConstraint.getAdditionalInfo());
                claimsCheckFound = true;
            } else if (MessageTag.EAA_SUPPORTED_CLAIMS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                supportedClaimsCheckFound = true;
            }
        }
        assertTrue(claimsCheckFound);
        assertFalse(supportedClaimsCheckFound);

        checkReports(reports);
    }

    @Test
    void claimsNotSupportedTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        DiagnosticData diagnosticData = new DiagnosticData(xmlDiagnosticData);
        AttestationWrapper attestationWrapper = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());

        MultiValuesConstraint claims = new MultiValuesConstraint();
        claims.setLevel(Level.FAIL);
        claims.getId().add("given_name");
        claims.getId().add("family_name");
        claims.getId().add("birthdate");
        validationPolicy.getEAAConstraints().setEAAClaims(claims);

        MultiValuesConstraint supportedClaims = new MultiValuesConstraint();
        supportedClaims.setLevel(Level.FAIL);
        supportedClaims.getId().addAll(attestationWrapper.getAllEAAPayloadClaimNames());
        supportedClaims.getId().remove("phone_number");
        supportedClaims.getId().remove("phone_number_verified");
        validationPolicy.getEAAConstraints().setEAASupportedClaims(supportedClaims);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_SUPPORTED_CLAIMS_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean claimsCheckFound = false;
        boolean supportedClaimsCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_CLAIMS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                claimsCheckFound = true;
            } else if (MessageTag.EAA_SUPPORTED_CLAIMS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_SUPPORTED_CLAIMS_ANS.getId(), xmlConstraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_UNSUPPORTED_CLAIMS, "phone_number, phone_number_verified"), xmlConstraint.getAdditionalInfo());
                supportedClaimsCheckFound = true;
            }
        }
        assertTrue(claimsCheckFound);
        assertTrue(supportedClaimsCheckFound);

        checkReports(reports);
    }

    @Test
    void claimNamespacesNotSupportedFailTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_mdoc.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint claims = new MultiValuesConstraint();
        claims.setLevel(Level.FAIL);
        claims.getId().add("org.iso.18013.5.1");
        validationPolicy.getEAAConstraints().setEAASupportedNamespaces(claims);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_SUPPORTED_CLAIM_NAMESPACES_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean supportedNamespacesCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_SUPPORTED_CLAIM_NAMESPACES.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_SUPPORTED_CLAIM_NAMESPACES_ANS.getId(), xmlConstraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_UNSUPPORTED_CLAIM_NAMESPACES, "org.etsi.01947201.010101"), xmlConstraint.getAdditionalInfo());
                supportedNamespacesCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(supportedNamespacesCheckFound);

        checkReports(reports);
    }

    @Test
    void claimNamespacesNotSupportedWarnTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_mdoc.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint claims = new MultiValuesConstraint();
        claims.setLevel(Level.WARN);
        claims.getId().add("org.iso.18013.5.1");
        validationPolicy.getEAAConstraints().setEAASupportedNamespaces(claims);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_SUPPORTED_CLAIM_NAMESPACES_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean supportedNamespacesCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_SUPPORTED_CLAIM_NAMESPACES.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_SUPPORTED_CLAIM_NAMESPACES_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_UNSUPPORTED_CLAIM_NAMESPACES, "org.etsi.01947201.010101"), xmlConstraint.getAdditionalInfo());
                supportedNamespacesCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(supportedNamespacesCheckFound);

        checkReports(reports);
    }

    @Test
    void eaaCategoryTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("urn:etsi:esi:eaa:eu:qualified");
        validationPolicy.getEAAConstraints().setEAACategory(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_CAT_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean checkFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_CAT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_CAT_ANS.getId(), xmlConstraint.getError().getKey());
                checkFound = true;
            }
        }
        assertTrue(checkFound);

        checkReports(reports);
    }

    @Test
    void eaaSubjectTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("user_xx");
        validationPolicy.getEAAConstraints().setEAASubject(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_SUB_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean checkFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                checkFound = true;
            }
        }
        assertTrue(checkFound);

        checkReports(reports);
    }

    @Test
    void eaaSubjectPseudonymTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("pseudonym");
        validationPolicy.getEAAConstraints().setEAASubjectPseudonym(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_SUB_PSE_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean checkFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_SUB_PSE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_SUB_PSE_ANS.getId(), xmlConstraint.getError().getKey());
                checkFound = true;
            }
        }
        assertTrue(checkFound);

        checkReports(reports);
    }

    @Test
    void eaaIssuingCountryTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("LU");
        validationPolicy.getEAAConstraints().setEAAIssuingCountry(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_ISS_COUN_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean checkFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_ISS_COUN.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_ISS_COUN_ANS.getId(), xmlConstraint.getError().getKey());
                checkFound = true;
            }
        }
        assertTrue(checkFound);

        checkReports(reports);
    }

    @Test
    void eaaIssuingAuthorityTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("Example Authority");
        validationPolicy.getEAAConstraints().setEAAIssuingAuthority(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_ISS_AUTH_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean checkFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_ISS_AUTH.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_ISS_AUTH_ANS.getId(), xmlConstraint.getError().getKey());
                checkFound = true;
            }
        }
        assertTrue(checkFound);

        checkReports(reports);
    }

    @Test
    void eaaIssuingAuthorityRegistrationIdentifierTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("VAT-12345");
        validationPolicy.getEAAConstraints().setEAAIssuingAuthorityRegistrationIdentifier(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_ISS_REG_ID_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean checkFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_ISS_REG_ID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_ISS_REG_ID_ANS.getId(), xmlConstraint.getError().getKey());
                checkFound = true;
            }
        }
        assertTrue(checkFound);

        checkReports(reports);
    }

    @Test
    void EAARevocationPresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlEAAPayload eaaPayload = xmlDiagnosticData.getEAAs().get(0).getEAAPayload();
        eaaPayload.setStatus(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getEAAConstraints().setEAARevocationPresent(constraint);

        LevelConstraint infoConstraint = new LevelConstraint();
        infoConstraint.setLevel(Level.INFORM);
        validationPolicy.getEAAConstraints().setEAAShortLived(infoConstraint);
        validationPolicy.getEAAConstraints().setEAAOneTimeUse(infoConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_PR_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean shortLivedCheckFound = false;
        boolean oneTimeCheckFound = false;
        boolean statusCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_SH_LVD.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                shortLivedCheckFound = true;
            } else if (MessageTag.EAA_OTU.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                oneTimeCheckFound = true;
            } else if (MessageTag.EAA_REV_PR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_PR_ANS.getId(), xmlConstraint.getError().getKey());
                statusCheckFound = true;
            }
        }
        assertFalse(shortLivedCheckFound);
        assertFalse(oneTimeCheckFound);
        assertTrue(statusCheckFound);

        checkReports(reports);
    }

    @Test
    void eaaShortLivedTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlEAAPayload eaaPayload = xmlDiagnosticData.getEAAs().get(0).getEAAPayload();
        eaaPayload.setStatus(null);
        XmlClaim xmlClaim = new XmlClaim();
        eaaPayload.setShortLived(xmlClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getEAAConstraints().setEAARevocationPresent(constraint);

        LevelConstraint infoConstraint = new LevelConstraint();
        infoConstraint.setLevel(Level.INFORM);
        validationPolicy.getEAAConstraints().setEAAShortLived(infoConstraint);
        validationPolicy.getEAAConstraints().setEAAOneTimeUse(infoConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_SH_LVD_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean shortLivedCheckFound = false;
        boolean oneTimeCheckFound = false;
        boolean statusCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_SH_LVD.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_SH_LVD_ANS.getId(), xmlConstraint.getInfo().getKey());
                shortLivedCheckFound = true;
            } else if (MessageTag.EAA_OTU.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                oneTimeCheckFound = true;
            } else if (MessageTag.EAA_REV_PR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusCheckFound = true;
            }
        }
        assertTrue(shortLivedCheckFound);
        assertFalse(oneTimeCheckFound);
        assertFalse(statusCheckFound);

        checkReports(reports);
    }

    @Test
    void eaaOneTimeTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlEAAPayload eaaPayload = xmlDiagnosticData.getEAAs().get(0).getEAAPayload();
        eaaPayload.setStatus(null);
        XmlClaim xmlClaim = new XmlClaim();
        eaaPayload.setOneTimeUse(xmlClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getEAAConstraints().setEAARevocationPresent(constraint);

        LevelConstraint infoConstraint = new LevelConstraint();
        infoConstraint.setLevel(Level.INFORM);
        validationPolicy.getEAAConstraints().setEAAShortLived(infoConstraint);
        validationPolicy.getEAAConstraints().setEAAOneTimeUse(infoConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_PR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_OTU_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean shortLivedCheckFound = false;
        boolean oneTimeCheckFound = false;
        boolean statusCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_SH_LVD.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                shortLivedCheckFound = true;
            } else if (MessageTag.EAA_OTU.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_OTU_ANS.getId(), xmlConstraint.getInfo().getKey());
                oneTimeCheckFound = true;
            } else if (MessageTag.EAA_REV_PR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_PR_ANS.getId(), xmlConstraint.getWarning().getKey());
                statusCheckFound = true;
            }
        }
        assertFalse(shortLivedCheckFound);
        assertTrue(oneTimeCheckFound);
        assertTrue(statusCheckFound);

        checkReports(reports);
    }

    @Test
    void eaaNoPseudonymUsePresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.INFORM);
        validationPolicy.getEAAConstraints().setEAAUsePseudonym(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean checkFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_PSEUDO_USED.getId().equals(xmlConstraint.getName().getKey())) {
                checkFound = true;
            }
        }
        assertFalse(checkFound);

        checkReports(reports);
    }

    @Test
    void eaaPseudonymUsePresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlEAAPayload eaaPayload = xmlDiagnosticData.getEAAs().get(0).getEAAPayload();
        XmlClaim xmlClaim = new XmlClaim();
        xmlClaim.setText("pseudonym");
        eaaPayload.setPseudonym(xmlClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.INFORM);
        validationPolicy.getEAAConstraints().setEAAUsePseudonym(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_PSEUDO_USED_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean checkFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_PSEUDO_USED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_PSEUDO_USED_ANS.getId(), xmlConstraint.getInfo().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.PSEUDO, "pseudonym"), xmlConstraint.getAdditionalInfo());
                checkFound = true;
            }
        }
        assertTrue(checkFound);

        checkReports(reports);
    }

    @Test
    void statusCheckValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationToken eaaRevocationToken = diagnosticData.getUsedEAARevocationTokens().get(0);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getEAAConstraints().setEAARevocationPresent(levelConstraint);
        validationPolicy.getEAAConstraints().setEAARevocationAvailable(levelConstraint);
        validationPolicy.getEAAConstraints().setAcceptableEAARevocationFound(levelConstraint);
        validationPolicy.getEAAConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getEAAConstraints().setNotOnHold(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownStatusCheckFound = false;
        boolean acceptableStatusCheckFound = false;
        boolean acceptableStatusFoundCheckFound = false;
        boolean notRevokedCheckFound = false;
        boolean notOnHoldCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_REV_PR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusPresentCheckFound = true;
            } else if (MessageTag.EAA_REV_AV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusAvailableCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                unknownStatusCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.TOKEN_ID, eaaRevocationToken.getId()), xmlConstraint.getAdditionalInfo());
                acceptableStatusCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC_FND.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.TOKEN_ID, eaaRevocationToken.getId()), xmlConstraint.getAdditionalInfo());
                acceptableStatusFoundCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_REV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                notRevokedCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_ON_HOLD.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                notOnHoldCheckFound = true;
            }
        }
        assertTrue(statusPresentCheckFound);
        assertTrue(statusAvailableCheckFound);
        assertTrue(unknownStatusCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertTrue(notRevokedCheckFound);
        assertTrue(notOnHoldCheckFound);

        assertNull(eaaBBB.getISC());
        assertNull(eaaBBB.getVCI());
        assertNull(eaaBBB.getXCV());

        XmlBasicBuildingBlocks eaaRevocationBBB = detailedReport.getBasicBuildingBlockById(eaaRevocationToken.getId());
        assertNotNull(eaaRevocationBBB);

        assertNotNull(eaaRevocationBBB.getFC());
        assertNotNull(eaaRevocationBBB.getISC());
        assertNotNull(eaaRevocationBBB.getXCV());
        assertNotNull(eaaRevocationBBB.getCV());
        assertNotNull(eaaRevocationBBB.getAOV());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean issTimeCheckFound = false;
        boolean expTimeCheckFound = false;
        boolean notExpiredCheckFound = false;
        boolean subjectCheckFound = false;
        boolean subjectMatchCheckFound = false;
        boolean eaaRevocationIssuerCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_REV_ISS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                issTimeCheckFound = true;
            } else if (MessageTag.EAA_REV_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                expTimeCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_REV_TIME,
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(eaaRevocationToken.getIssuedAt()),
                        ValidationProcessUtils.getFormattedDate(eaaRevocationToken.getExpirationTime())), xmlConstraint.getAdditionalInfo());
                notExpiredCheckFound = true;
            } else if (MessageTag.EAA_REV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                subjectCheckFound = true;
            } else if (MessageTag.EAA_REV_SUB_MATCH.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                subjectMatchCheckFound = true;
            } else if (MessageTag.EAA_REV_ISS_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.EAA_REV_ISS_CERT,
                                ValidationProcessUtils.getFormattedDate(eaaRevocationToken.getIssuedAt()),
                                ValidationProcessUtils.getFormattedDate(eaaRevocationToken.getSigningCertificate().getCertificate().getNotBefore()),
                                ValidationProcessUtils.getFormattedDate(eaaRevocationToken.getSigningCertificate().getCertificate().getNotAfter())),
                        xmlConstraint.getAdditionalInfo());
                eaaRevocationIssuerCheckFound = true;
            }
        }
        assertTrue(issTimeCheckFound);
        assertTrue(expTimeCheckFound);
        assertTrue(notExpiredCheckFound);
        assertTrue(subjectCheckFound);
        assertTrue(subjectMatchCheckFound);
        assertTrue(eaaRevocationIssuerCheckFound);

        assertNull(eaaRevocationBBB.getVCI());

        checkReports(reports);
    }

    @Test
    void statusNotAvailableTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getEAAs().get(0).getAttestationRevocations().clear();

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getEAAConstraints().setEAARevocationPresent(levelConstraint);
        validationPolicy.getEAAConstraints().setEAARevocationAvailable(levelConstraint);
        validationPolicy.getEAAConstraints().setAcceptableEAARevocationFound(levelConstraint);
        validationPolicy.getEAAConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getEAAConstraints().setNotOnHold(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_AV_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean acceptableStatusCheckFound = false;
        boolean acceptableStatusFoundCheckFound = false;
        boolean notRevokedCheckFound = false;
        boolean notOnHoldCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_REV_PR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusPresentCheckFound = true;
            } else if (MessageTag.EAA_REV_AV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_AV_ANS.getId(), xmlConstraint.getError().getKey());
                statusAvailableCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                acceptableStatusCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC_FND.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                acceptableStatusFoundCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_REV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                notRevokedCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_ON_HOLD.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                notOnHoldCheckFound = true;
            }
        }
        assertTrue(statusPresentCheckFound);
        assertTrue(statusAvailableCheckFound);
        assertFalse(acceptableStatusCheckFound);
        assertFalse(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

        assertNull(eaaBBB.getISC());
        assertNull(eaaBBB.getVCI());
        assertNull(eaaBBB.getXCV());

        checkReports(reports);
    }

    @Test
    void statusNoTypeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationToken eaaRevocationToken = diagnosticData.getUsedEAARevocationTokens().get(0);
        eaaRevocationToken.setType(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getEAAConstraints().setEAARevocationPresent(levelConstraint);
        validationPolicy.getEAAConstraints().setEAARevocationAvailable(levelConstraint);
        validationPolicy.getEAAConstraints().setAcceptableEAARevocationFound(levelConstraint);
        validationPolicy.getEAAConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getEAAConstraints().setNotOnHold(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_ACC_FND_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean acceptableStatusCheckFound = false;
        boolean acceptableStatusFoundCheckFound = false;
        boolean notRevokedCheckFound = false;
        boolean notOnHoldCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_REV_PR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusPresentCheckFound = true;
            } else if (MessageTag.EAA_REV_AV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusAvailableCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_ACC_ANS.getId(), xmlConstraint.getWarning().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.TOKEN_ID, eaaRevocationToken.getId()), xmlConstraint.getAdditionalInfo());
                acceptableStatusCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC_FND.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_ACC_FND_ANS.getId(), xmlConstraint.getError().getKey());
                assertNull(xmlConstraint.getAdditionalInfo());
                acceptableStatusFoundCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_REV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                notRevokedCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_ON_HOLD.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                notOnHoldCheckFound = true;
            }
        }
        assertTrue(statusPresentCheckFound);
        assertTrue(statusAvailableCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

        assertNull(eaaBBB.getISC());
        assertNull(eaaBBB.getVCI());
        assertNull(eaaBBB.getXCV());

        XmlBasicBuildingBlocks eaaRevocationBBB = detailedReport.getBasicBuildingBlockById(eaaRevocationToken.getId());
        assertNotNull(eaaRevocationBBB);

        xmlFC = eaaRevocationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.FAILED, xmlFC.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, xmlFC.getConclusion().getSubIndication());

        boolean typeCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            if (MessageTag.EAA_REV_TYPE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_TYPE_ANS.getId(), xmlConstraint.getError().getKey());
                typeCheckFound = true;
            }
        }
        assertTrue(typeCheckFound);

        assertNotNull(eaaRevocationBBB.getISC());
        assertNotNull(eaaRevocationBBB.getXCV());
        assertNotNull(eaaRevocationBBB.getCV());
        assertNotNull(eaaRevocationBBB.getSAV());
        assertNotNull(eaaRevocationBBB.getAOV());
        assertNull(eaaRevocationBBB.getVCI());

        checkReports(reports);
    }

    @Test
    void statusInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0).setStatus(AttestationStatus.INVALID);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getEAAConstraints().setEAARevocationPresent(levelConstraint);
        validationPolicy.getEAAConstraints().setEAARevocationAvailable(levelConstraint);
        validationPolicy.getEAAConstraints().setAcceptableEAARevocationFound(levelConstraint);
        validationPolicy.getEAAConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getEAAConstraints().setNotOnHold(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.REVOKED, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_REV_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.REVOKED, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.FAILED, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.FAILED, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED, xmlSAV.getConclusion().getSubIndication());

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean acceptableStatusCheckFound = false;
        boolean acceptableStatusFoundCheckFound = false;
        boolean notRevokedCheckFound = false;
        boolean notOnHoldCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_REV_PR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusPresentCheckFound = true;
            } else if (MessageTag.EAA_REV_AV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusAvailableCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                acceptableStatusCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC_FND.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                acceptableStatusFoundCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_REV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_NOT_REV_ANS.getId(), xmlConstraint.getError().getKey());
                notRevokedCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_ON_HOLD.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                notOnHoldCheckFound = true;
            }
        }
        assertTrue(statusPresentCheckFound);
        assertTrue(statusAvailableCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertTrue(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

        assertNull(eaaBBB.getISC());
        assertNull(eaaBBB.getVCI());
        assertNull(eaaBBB.getXCV());

        checkReports(reports);
    }

    @Test
    void statusSuspendedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0).setStatus(AttestationStatus.SUSPENDED);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getEAAConstraints().setEAARevocationPresent(levelConstraint);
        validationPolicy.getEAAConstraints().setEAARevocationAvailable(levelConstraint);
        validationPolicy.getEAAConstraints().setAcceptableEAARevocationFound(levelConstraint);
        validationPolicy.getEAAConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getEAAConstraints().setNotOnHold(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_ON_HOLD_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.TRY_LATER, detailedReport.getFinalSubIndication(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.INDETERMINATE, validationProcessEAA.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessEAA.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        XmlCV xmlCV = eaaBBB.getCV();
        assertNotNull(xmlCV);

        XmlAOV xmlAOV = eaaBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = eaaBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, xmlSAV.getConclusion().getSubIndication());

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean acceptableStatusCheckFound = false;
        boolean acceptableStatusFoundCheckFound = false;
        boolean notRevokedCheckFound = false;
        boolean notOnHoldCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_REV_PR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusPresentCheckFound = true;
            } else if (MessageTag.EAA_REV_AV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusAvailableCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                acceptableStatusCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC_FND.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                acceptableStatusFoundCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_REV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                notRevokedCheckFound = true;
            } else if (MessageTag.EAA_REV_NOT_ON_HOLD.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_NOT_ON_HOLD_ANS.getId(), xmlConstraint.getError().getKey());
                notOnHoldCheckFound = true;
            }
        }
        assertTrue(statusPresentCheckFound);
        assertTrue(statusAvailableCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertTrue(notRevokedCheckFound);
        assertTrue(notOnHoldCheckFound);

        assertNull(eaaBBB.getISC());
        assertNull(eaaBBB.getVCI());
        assertNull(eaaBBB.getXCV());

        checkReports(reports);
    }

    @Override
    protected EtsiValidationPolicy loadDefaultPolicy() throws Exception {
        return (EtsiValidationPolicy) ValidationPolicyLoader.fromValidationPolicy(EAA_POLICY_LOCATION).create();
    }

}
