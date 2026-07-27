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
import eu.europa.esig.dss.detailedreport.jaxb.XmlAttestation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessAttestation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationRevocationToken;
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
import eu.europa.esig.dss.validation.executor.attestation.AttestationProcessExecutor;
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

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessAttestation.getConstraint()) {
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

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
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

        XmlCV xmlCV = attestationBBB.getCV();
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

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);

        assertNull(attestationBBB.getISC());
        assertNull(attestationBBB.getVCI());
        assertNull(attestationBBB.getXCV());

        checkReports(reports);
    }

    @Test
    void validWithOrphanDisclosuresTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getAttestations().get(0).getDigestMatchers();

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM);
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

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessAttestation.getConstraint()) {
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

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
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

        XmlCV xmlCV = attestationBBB.getCV();
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

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);

        checkReports(reports);
    }

    @Test
    void disclosureNotIntactTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getAttestations().get(0).getDigestMatchers();
        digestMatchers.get(0).setDataIntact(false);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.BBB_CV_EAA_SDCBI_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.HASH_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.FAILED, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessAttestation.getConstraint()) {
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

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
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

        XmlCV xmlCV = attestationBBB.getCV();
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

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
        validationPolicy.getAttestationConstraints().setDisclosurePresent(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_DPEAAP_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessAttestation.getConstraint()) {
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

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
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

        XmlCV xmlCV = attestationBBB.getCV();
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

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
        validationPolicy.getAttestationConstraints().setDisclosurePresent(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));

        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_DPEAAP_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.FAILED, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessAttestation.getConstraint()) {
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

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
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

        XmlCV xmlCV = attestationBBB.getCV();
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

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.ADEST_IBSVPSC_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        List<XmlSignature> attestationSignatures = simpleReport.getAttestationSignatures(simpleReport.getFirstAttestationId());
        assertEquals(1, attestationSignatures.size());
        XmlSignature attestationSignature = attestationSignatures.get(0);

        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(attestationSignature.getId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(attestationSignature.getId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(attestationSignature.getId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(attestationSignature.getId()), i18nProvider.getMessage(MessageTag.BBB_FC_IEFF_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(attestationSignature.getId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(attestationSignature.getId())));

        XmlSignature keyBindingSignature = simpleReport.getAttestationKeyBindingSignature(simpleReport.getFirstAttestationId());
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(keyBindingSignature.getId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(keyBindingSignature.getId())));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(keyBindingSignature.getId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(keyBindingSignature.getId()), i18nProvider.getMessage(MessageTag.BBB_ICS_ISCI_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(keyBindingSignature.getId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.FAILED, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessAttestation.getConstraint()) {
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

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
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

        XmlCV xmlCV = attestationBBB.getCV();
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

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_KBRC_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        List<XmlSignature> attestationSignatures = simpleReport.getAttestationSignatures(simpleReport.getFirstAttestationId());
        assertEquals(1, attestationSignatures.size());
        XmlSignature attestationSignature = attestationSignatures.get(0);

        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(attestationSignature.getId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(attestationSignature.getId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(attestationSignature.getId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(attestationSignature.getId())));

        XmlSignature keyBindingSignature = simpleReport.getAttestationKeyBindingSignature(simpleReport.getFirstAttestationId());
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(keyBindingSignature.getId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(keyBindingSignature.getId()));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(keyBindingSignature.getId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(keyBindingSignature.getId()), i18nProvider.getMessage(MessageTag.BBB_FC_IEFF_ANS)));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(keyBindingSignature.getId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(keyBindingSignature.getId()), i18nProvider.getMessage(MessageTag.BBB_ICS_ISCI_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(keyBindingSignature.getId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.FAILED, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessAttestation.getConstraint()) {
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

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
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

        XmlCV xmlCV = attestationBBB.getCV();
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

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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

        XmlAttestationPayload attestationPayload = diagnosticData.getAttestations().get(0).getAttestationPayload();
        XmlClaim expirationClaim = new XmlClaim();
        expirationClaim.setDateTime(calendar.getTime());
        attestationPayload.setExpiration(expirationClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getAttestationConstraints().setNotExpired(levelConstraint);
        validationPolicy.getAttestationConstraints().setAdministrativePeriodNotExpired(levelConstraint);

        LevelConstraint etsiConstraint = new LevelConstraint();
        etsiConstraint.setLevel(Level.WARN);
        validationPolicy.getAttestationConstraints().setETSI194721Conformance(etsiConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));

        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_VT_ITVR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_ETSI194721_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessAttestation.getConclusion().getSubIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        boolean kbSigValidationConclusiveCheckFound = false;
        boolean cvCheckFound = false;
        boolean savCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessAttestation.getConstraint()) {
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

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getExpiration().getDateTime())), xmlConstraint.getAdditionalInfo());
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
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getNotBefore().getDateTime()),
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getExpiration().getDateTime())), xmlConstraint.getAdditionalInfo());
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

        XmlAttestationPayload attestationPayload = diagnosticData.getAttestations().get(0).getAttestationPayload();
        XmlClaim expirationClaim = new XmlClaim();
        expirationClaim.setDateTime(calendar.getTime());
        attestationPayload.setExpiration(expirationClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getAttestationConstraints().setNotExpired(levelConstraint);
        validationPolicy.getAttestationConstraints().setAdministrativePeriodNotExpired(levelConstraint);

        LevelConstraint etsiConstraint = new LevelConstraint();
        etsiConstraint.setLevel(Level.WARN);
        validationPolicy.getAttestationConstraints().setETSI194721Conformance(etsiConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));

        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_VT_ITVR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_ETSI194721_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getExpiration().getDateTime())), xmlConstraint.getAdditionalInfo());
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
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getNotBefore().getDateTime()),
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getExpiration().getDateTime())), xmlConstraint.getAdditionalInfo());
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

        XmlAttestationPayload attestationPayload = diagnosticData.getAttestations().get(0).getAttestationPayload();
        XmlClaim expirationClaim = new XmlClaim();
        expirationClaim.setDateTime(calendar.getTime());
        attestationPayload.setExpiration(expirationClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getAttestationConstraints().setNotExpired(levelConstraint);
        validationPolicy.getAttestationConstraints().setAdministrativePeriodNotExpired(levelConstraint);

        LevelConstraint etsiConstraint = new LevelConstraint();
        etsiConstraint.setLevel(Level.FAIL);
        validationPolicy.getAttestationConstraints().setETSI194721Conformance(etsiConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));

        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_ETSI194721_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getExpiration().getDateTime())), xmlConstraint.getAdditionalInfo());
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

        XmlAttestationPayload attestationPayload = diagnosticData.getAttestations().get(0).getAttestationPayload();
        attestationPayload.setAdministrativeIssuanceDate(attestationPayload.getNotBefore());

        XmlClaim expirationClaim = new XmlClaim();
        expirationClaim.setDateTime(calendar.getTime());
        attestationPayload.setAdministrativeExpirationDate(expirationClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getAttestationConstraints().setNotExpired(levelConstraint);
        validationPolicy.getAttestationConstraints().setAdministrativePeriodNotExpired(levelConstraint);

        LevelConstraint etsiConstraint = new LevelConstraint();
        etsiConstraint.setLevel(Level.WARN);
        validationPolicy.getAttestationConstraints().setETSI194721Conformance(etsiConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));

        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_VT_IAVR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_ETSI194721_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getAdministrativeExpirationDate().getDateTime())), xmlConstraint.getAdditionalInfo());
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
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getAdministrativeIssuanceDate().getDateTime()),
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getAdministrativeExpirationDate().getDateTime())), xmlConstraint.getAdditionalInfo());
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

        XmlAttestationPayload attestationPayload = diagnosticData.getAttestations().get(0).getAttestationPayload();
        attestationPayload.setAdministrativeIssuanceDate(attestationPayload.getNotBefore());

        XmlClaim expirationClaim = new XmlClaim();
        expirationClaim.setDateTime(calendar.getTime());
        attestationPayload.setAdministrativeExpirationDate(expirationClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getAttestationConstraints().setNotExpired(levelConstraint);
        validationPolicy.getAttestationConstraints().setAdministrativeIssuanceDatePresent(levelConstraint);
        validationPolicy.getAttestationConstraints().setAdministrativeExpirationDatePresent(levelConstraint);
        validationPolicy.getAttestationConstraints().setAdministrativePeriodNotExpired(levelConstraint);

        LevelConstraint etsiConstraint = new LevelConstraint();
        etsiConstraint.setLevel(Level.WARN);
        validationPolicy.getAttestationConstraints().setETSI194721Conformance(etsiConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));

        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_VT_IAVR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_ETSI194721_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getAdministrativeExpirationDate().getDateTime())), xmlConstraint.getAdditionalInfo());
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
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getAdministrativeIssuanceDate().getDateTime()),
                        ValidationProcessUtils.getFormattedDate(attestationPayload.getAdministrativeExpirationDate().getDateTime())), xmlConstraint.getAdditionalInfo());
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
        AttestationWrapper attestationWrapper = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());

        MultiValuesConstraint claims = new MultiValuesConstraint();
        claims.setLevel(Level.FAIL);
        claims.getId().add("given_name");
        claims.getId().add("family_name");
        claims.getId().add("birthdate");
        validationPolicy.getAttestationConstraints().setClaims(claims);

        MultiValuesConstraint supportedClaims = new MultiValuesConstraint();
        supportedClaims.setLevel(Level.FAIL);
        supportedClaims.getId().addAll(attestationWrapper.getAllAttestationPayloadClaimNames());
        validationPolicy.getAttestationConstraints().setSupportedClaims(supportedClaims);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
        AttestationWrapper attestationWrapper = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());

        MultiValuesConstraint claims = new MultiValuesConstraint();
        claims.setLevel(Level.FAIL);
        claims.getId().add("given_name");
        claims.getId().add("family_name");
        claims.getId().add("middle_name");
        claims.getId().add("birthdate");
        validationPolicy.getAttestationConstraints().setClaims(claims);

        MultiValuesConstraint supportedClaims = new MultiValuesConstraint();
        supportedClaims.setLevel(Level.FAIL);
        supportedClaims.getId().addAll(attestationWrapper.getAllAttestationPayloadClaimNames());
        validationPolicy.getAttestationConstraints().setSupportedClaims(supportedClaims);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_CLAIMS_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
        AttestationWrapper attestationWrapper = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());

        MultiValuesConstraint claims = new MultiValuesConstraint();
        claims.setLevel(Level.FAIL);
        claims.getId().add("given_name");
        claims.getId().add("family_name");
        claims.getId().add("birthdate");
        validationPolicy.getAttestationConstraints().setClaims(claims);

        MultiValuesConstraint supportedClaims = new MultiValuesConstraint();
        supportedClaims.setLevel(Level.FAIL);
        supportedClaims.getId().addAll(attestationWrapper.getAllAttestationPayloadClaimNames());
        supportedClaims.getId().remove("phone_number");
        supportedClaims.getId().remove("phone_number_verified");
        validationPolicy.getAttestationConstraints().setSupportedClaims(supportedClaims);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_SUPPORTED_CLAIMS_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
        validationPolicy.getAttestationConstraints().setSupportedNamespaces(claims);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_SUPPORTED_CLAIM_NAMESPACES_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
        validationPolicy.getAttestationConstraints().setSupportedNamespaces(claims);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_SUPPORTED_CLAIM_NAMESPACES_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
    void attestationCategoryTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("urn:etsi:esi:attestation:eu:qualified");
        validationPolicy.getAttestationConstraints().setCategory(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_CAT_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
    void attestationSubjectTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("user_xx");
        validationPolicy.getAttestationConstraints().setSubject(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_SUB_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
    void attestationSubjectPseudonymTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("pseudonym");
        validationPolicy.getAttestationConstraints().setPseudonym(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_SUB_PSE_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
    void attestationIssuingCountryTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("LU");
        validationPolicy.getAttestationConstraints().setIssuingCountry(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_ISS_COUN_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
    void attestationIssuingAuthorityTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("Example Authority");
        validationPolicy.getAttestationConstraints().setIssuingAuthority(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_ISS_AUTH_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
    void attestationIssuingAuthorityRegistrationIdentifierTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("VAT-12345");
        validationPolicy.getAttestationConstraints().setIssuingAuthorityRegistrationIdentifier(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_ISS_REG_ID_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
    void RevocationPresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlAttestationPayload attestationPayload = xmlDiagnosticData.getAttestations().get(0).getAttestationPayload();
        attestationPayload.setStatus(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getAttestationConstraints().setRevocationPresent(constraint);

        LevelConstraint infoConstraint = new LevelConstraint();
        infoConstraint.setLevel(Level.INFORM);
        validationPolicy.getAttestationConstraints().setShortLived(infoConstraint);
        validationPolicy.getAttestationConstraints().setOneTimeUse(infoConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_PR_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
    void attestationShortLivedTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlAttestationPayload attestationPayload = xmlDiagnosticData.getAttestations().get(0).getAttestationPayload();
        attestationPayload.setStatus(null);
        XmlClaim xmlClaim = new XmlClaim();
        attestationPayload.setShortLived(xmlClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getAttestationConstraints().setRevocationPresent(constraint);

        LevelConstraint infoConstraint = new LevelConstraint();
        infoConstraint.setLevel(Level.INFORM);
        validationPolicy.getAttestationConstraints().setShortLived(infoConstraint);
        validationPolicy.getAttestationConstraints().setOneTimeUse(infoConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_SH_LVD_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
    void attestationOneTimeTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlAttestationPayload attestationPayload = xmlDiagnosticData.getAttestations().get(0).getAttestationPayload();
        attestationPayload.setStatus(null);
        XmlClaim xmlClaim = new XmlClaim();
        attestationPayload.setOneTimeUse(xmlClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getAttestationConstraints().setRevocationPresent(constraint);

        LevelConstraint infoConstraint = new LevelConstraint();
        infoConstraint.setLevel(Level.INFORM);
        validationPolicy.getAttestationConstraints().setShortLived(infoConstraint);
        validationPolicy.getAttestationConstraints().setOneTimeUse(infoConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_PR_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_OTU_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
    void attestationNoPseudonymUsePresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.INFORM);
        validationPolicy.getAttestationConstraints().setUsePseudonym(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
    void attestationPseudonymUsePresentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlAttestationPayload attestationPayload = xmlDiagnosticData.getAttestations().get(0).getAttestationPayload();
        XmlClaim xmlClaim = new XmlClaim();
        xmlClaim.setText("pseudonym");
        attestationPayload.setPseudonym(xmlClaim);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.INFORM);
        validationPolicy.getAttestationConstraints().setUsePseudonym(constraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_PSEUDO_USED_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.PASSED, xmlCV.getConclusion().getIndication());

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);
        assertEquals(Indication.PASSED, xmlAOV.getConclusion().getIndication());

        XmlSAV xmlSAV = attestationBBB.getSAV();
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

        XmlAttestationRevocationToken attestationRevocationToken = diagnosticData.getUsedAttestationRevocationTokens().get(0);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getAttestationConstraints().setRevocationPresent(levelConstraint);
        validationPolicy.getAttestationConstraints().setRevocationAvailable(levelConstraint);
        validationPolicy.getAttestationConstraints().setAcceptableRevocationFound(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotOnHold(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.PASSED, validationProcessAttestation.getConclusion().getIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = attestationBBB.getSAV();
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
                assertEquals(i18nProvider.getMessage(MessageTag.TOKEN_ID, attestationRevocationToken.getId()), xmlConstraint.getAdditionalInfo());
                acceptableStatusCheckFound = true;
            } else if (MessageTag.EAA_REV_ACC_FND.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.TOKEN_ID, attestationRevocationToken.getId()), xmlConstraint.getAdditionalInfo());
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

        assertNull(attestationBBB.getISC());
        assertNull(attestationBBB.getVCI());
        assertNull(attestationBBB.getXCV());

        XmlBasicBuildingBlocks attestationRevocationBBB = detailedReport.getBasicBuildingBlockById(attestationRevocationToken.getId());
        assertNotNull(attestationRevocationBBB);

        assertNotNull(attestationRevocationBBB.getFC());
        assertNotNull(attestationRevocationBBB.getISC());
        assertNotNull(attestationRevocationBBB.getXCV());
        assertNotNull(attestationRevocationBBB.getCV());
        assertNotNull(attestationRevocationBBB.getAOV());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean issTimeCheckFound = false;
        boolean expTimeCheckFound = false;
        boolean notExpiredCheckFound = false;
        boolean subjectCheckFound = false;
        boolean subjectMatchCheckFound = false;
        boolean attestationRevocationIssuerCheckFound = false;
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
                        ValidationProcessUtils.getFormattedDate(attestationRevocationToken.getIssuedAt()),
                        ValidationProcessUtils.getFormattedDate(attestationRevocationToken.getExpirationTime())), xmlConstraint.getAdditionalInfo());
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
                                ValidationProcessUtils.getFormattedDate(attestationRevocationToken.getIssuedAt()),
                                ValidationProcessUtils.getFormattedDate(attestationRevocationToken.getSigningCertificate().getCertificate().getNotBefore()),
                                ValidationProcessUtils.getFormattedDate(attestationRevocationToken.getSigningCertificate().getCertificate().getNotAfter())),
                        xmlConstraint.getAdditionalInfo());
                attestationRevocationIssuerCheckFound = true;
            }
        }
        assertTrue(issTimeCheckFound);
        assertTrue(expTimeCheckFound);
        assertTrue(notExpiredCheckFound);
        assertTrue(subjectCheckFound);
        assertTrue(subjectMatchCheckFound);
        assertTrue(attestationRevocationIssuerCheckFound);

        assertNull(attestationRevocationBBB.getVCI());

        checkReports(reports);
    }

    @Test
    void statusNotAvailableTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getAttestations().get(0).getAttestationRevocations().clear();

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getAttestationConstraints().setRevocationPresent(levelConstraint);
        validationPolicy.getAttestationConstraints().setRevocationAvailable(levelConstraint);
        validationPolicy.getAttestationConstraints().setAcceptableRevocationFound(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotOnHold(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_AV_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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

        assertNull(attestationBBB.getISC());
        assertNull(attestationBBB.getVCI());
        assertNull(attestationBBB.getXCV());

        checkReports(reports);
    }

    @Test
    void statusNoTypeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationToken attestationRevocationToken = diagnosticData.getUsedAttestationRevocationTokens().get(0);
        attestationRevocationToken.setType(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getAttestationConstraints().setRevocationPresent(levelConstraint);
        validationPolicy.getAttestationConstraints().setRevocationAvailable(levelConstraint);
        validationPolicy.getAttestationConstraints().setAcceptableRevocationFound(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotOnHold(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_ACC_FND_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = attestationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

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
                assertEquals(i18nProvider.getMessage(MessageTag.TOKEN_ID, attestationRevocationToken.getId()), xmlConstraint.getAdditionalInfo());
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

        assertNull(attestationBBB.getISC());
        assertNull(attestationBBB.getVCI());
        assertNull(attestationBBB.getXCV());

        XmlBasicBuildingBlocks attestationRevocationBBB = detailedReport.getBasicBuildingBlockById(attestationRevocationToken.getId());
        assertNotNull(attestationRevocationBBB);

        xmlFC = attestationRevocationBBB.getFC();
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

        assertNotNull(attestationRevocationBBB.getISC());
        assertNotNull(attestationRevocationBBB.getXCV());
        assertNotNull(attestationRevocationBBB.getCV());
        assertNotNull(attestationRevocationBBB.getSAV());
        assertNotNull(attestationRevocationBBB.getAOV());
        assertNull(attestationRevocationBBB.getVCI());

        checkReports(reports);
    }

    @Test
    void statusInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0).setStatus(AttestationStatus.INVALID);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getAttestationConstraints().setRevocationPresent(levelConstraint);
        validationPolicy.getAttestationConstraints().setRevocationAvailable(levelConstraint);
        validationPolicy.getAttestationConstraints().setAcceptableRevocationFound(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotOnHold(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.REVOKED, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_REV_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.REVOKED, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.FAILED, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = attestationBBB.getSAV();
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

        assertNull(attestationBBB.getISC());
        assertNull(attestationBBB.getVCI());
        assertNull(attestationBBB.getXCV());

        checkReports(reports);
    }

    @Test
    void statusSuspendedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0).setStatus(AttestationStatus.SUSPENDED);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getAttestationConstraints().setRevocationPresent(levelConstraint);
        validationPolicy.getAttestationConstraints().setRevocationAvailable(levelConstraint);
        validationPolicy.getAttestationConstraints().setAcceptableRevocationFound(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotOnHold(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_ON_HOLD_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstAttestationId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.TRY_LATER, detailedReport.getFinalSubIndication(simpleReport.getFirstAttestationId()));

        XmlAttestation xmlAttestation = detailedReport.getXmlAttestationById(detailedReport.getFirstAttestationId());
        assertNotNull(xmlAttestation);

        XmlValidationProcessAttestation validationProcessAttestation = xmlAttestation.getValidationProcessAttestation();
        assertNotNull(validationProcessAttestation);
        assertEquals(Indication.INDETERMINATE, validationProcessAttestation.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessAttestation.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks attestationBBB = detailedReport.getBasicBuildingBlockById(xmlAttestation.getId());
        assertNotNull(attestationBBB);

        XmlFC xmlFC = attestationBBB.getFC();
        assertNotNull(xmlFC);

        XmlCV xmlCV = attestationBBB.getCV();
        assertNotNull(xmlCV);

        XmlAOV xmlAOV = attestationBBB.getAOV();
        assertNotNull(xmlAOV);

        XmlSAV xmlSAV = attestationBBB.getSAV();
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

        assertNull(attestationBBB.getISC());
        assertNull(attestationBBB.getVCI());
        assertNull(attestationBBB.getXCV());

        checkReports(reports);
    }

    @Override
    protected EtsiValidationPolicy loadDefaultPolicy() throws Exception {
        return (EtsiValidationPolicy) ValidationPolicyLoader.fromValidationPolicy(EAA_POLICY_LOCATION).create();
    }

}
