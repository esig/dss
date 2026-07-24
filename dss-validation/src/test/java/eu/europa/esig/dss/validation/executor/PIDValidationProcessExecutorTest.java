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
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEAA;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationEAAQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationEAAQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationPIDQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEAA;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlListOfTrustedEntities;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedEntity;
import eu.europa.esig.dss.enumerations.AttestationQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.LoTEServiceTypeIdentifierEnum;
import eu.europa.esig.dss.enumerations.LoTETypeEnum;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.eaa.AttestationProcessExecutor;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PIDValidationProcessExecutorTest extends AbstractTestValidationExecutor {

    private static final String PID_POLICY_LOCATION = "/policy/eaa-constraint.xml";

    private static I18nProvider i18nProvider;

    @BeforeAll
    static void init() {
        i18nProvider = new I18nProvider(Locale.getDefault());
    }

    @Test
    void validTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_pid.xml"));
        assertNotNull(diagnosticData);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(AttestationQualification.PID, simpleReport.getEAAQualification(simpleReport.getFirstEAAId()));
        assertEquals(Collections.singletonList(AttestationQualification.PID), simpleReport.getEAAQualifications(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Collections.singletonList(AttestationQualification.PID), detailedReport.getEAAQualifications(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                sigValidationConclusiveCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        boolean sigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                sigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);

        XmlValidationEAAQualification validationEAAQualification = xmlEAA.getValidationEAAQualification();
        assertNotNull(validationEAAQualification);
        assertEquals(Indication.PASSED, validationEAAQualification.getConclusion().getIndication());

        boolean trustAnchorListCheckFound = false;
        boolean eaaQualConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationEAAQualification.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_CERT_TRUST_ANCHOR_LIST_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                trustAnchorListCheckFound = true;
            } else if (MessageTag.EAA_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                eaaQualConclusiveCheckFound = true;
            }
        }
        assertTrue(trustAnchorListCheckFound);
        assertTrue(eaaQualConclusiveCheckFound);

        XmlValidationEAAQualificationProcess eaaQualificationProcess = validationEAAQualification.getValidationEAAQualificationProcess();
        assertNotNull(eaaQualificationProcess);
        assertEquals(Indication.FAILED, eaaQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, eaaQualificationProcess.getEAAQualification());

        XmlValidationPIDQualificationProcess pidQualificationProcess = validationEAAQualification.getValidationPIDQualificationProcess();
        assertNotNull(pidQualificationProcess);
        assertEquals(Indication.PASSED, pidQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.PID, pidQualificationProcess.getEAAQualification());

        boolean loteReachedCheckFound = false;
        boolean pidDocumentTypeCheckFound = false;
        boolean loteAcceptableCheckFound = false;
        boolean loteTypeForPIDProvidersCheckFound = false;
        boolean acceptableLoTEFoundCheckFound = false;
        boolean certForPIDIssuanceCheckFound = false;
        boolean certForPIDIssuanceAtIssuanceTimeCheckFound = false;
        boolean certForPIDIssuanceAtValidationTimeCheckFound = false;
        for (XmlConstraint xmlConstraint : pidQualificationProcess.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_CERT_LOTE_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                loteReachedCheckFound = true;
            } else if (MessageTag.PID_DOCUMENT_TYPE.getId().equals(xmlConstraint.getName().getKey())) {
                pidDocumentTypeCheckFound = true;
            } else if (MessageTag.CERT_USAGE_LOTE_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                loteAcceptableCheckFound = true;
            } else if (MessageTag.PID_LOTE_TYPE_PID_PROVIDERS.getId().equals(xmlConstraint.getName().getKey())) {
                loteTypeForPIDProvidersCheckFound = true;
            } else if (MessageTag.CERT_USAGE_VALID_LOTE_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                acceptableLoTEFoundCheckFound = true;
            } else if (MessageTag.PID_STI_PID_ISSUANCE.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_ISSUANCE_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtIssuanceTimeCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_VALIDATION_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtValidationTimeCheckFound = true;
            }
        }
        assertTrue(loteReachedCheckFound);
        assertTrue(pidDocumentTypeCheckFound);
        assertTrue(loteAcceptableCheckFound);
        assertTrue(loteTypeForPIDProvidersCheckFound);
        assertTrue(acceptableLoTEFoundCheckFound);
        assertTrue(certForPIDIssuanceCheckFound);
        assertTrue(certForPIDIssuanceAtIssuanceTimeCheckFound);
        assertTrue(certForPIDIssuanceAtValidationTimeCheckFound);

        checkReports(reports);
    }

    @Test
    void noLoTETest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_pid.xml"));
        assertNotNull(diagnosticData);

        XmlSigningCertificate signingCertificate = diagnosticData.getEAAs().get(0)
                .getEAASignature().get(0).getSignature().getSigningCertificate();
        signingCertificate.getCertificate().getTrustedEntities().clear();

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(AttestationQualification.NA, simpleReport.getEAAQualification(simpleReport.getFirstEAAId()));
        assertEquals(Collections.singletonList(AttestationQualification.NA), simpleReport.getEAAQualifications(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.EAA_CERT_TRUST_ANCHOR_LIST_REACHED_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Collections.singletonList(AttestationQualification.NA), detailedReport.getEAAQualifications(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                sigValidationConclusiveCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        boolean sigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                sigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);

        XmlValidationEAAQualification validationEAAQualification = xmlEAA.getValidationEAAQualification();
        assertNotNull(validationEAAQualification);
        assertEquals(Indication.FAILED, validationEAAQualification.getConclusion().getIndication());

        boolean trustAnchorListCheckFound = false;
        boolean eaaQualConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationEAAQualification.getConstraint()) {
            if (MessageTag.EAA_CERT_TRUST_ANCHOR_LIST_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_CERT_TRUST_ANCHOR_LIST_REACHED_ANS.getId(), xmlConstraint.getError().getKey());
                trustAnchorListCheckFound = true;
            } else if (MessageTag.EAA_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                eaaQualConclusiveCheckFound = true;
            }
        }
        assertTrue(trustAnchorListCheckFound);
        assertFalse(eaaQualConclusiveCheckFound);

        XmlValidationEAAQualificationProcess eaaQualificationProcess = validationEAAQualification.getValidationEAAQualificationProcess();
        assertNotNull(eaaQualificationProcess);
        assertEquals(Indication.FAILED, eaaQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, eaaQualificationProcess.getEAAQualification());

        XmlValidationPIDQualificationProcess pidQualificationProcess = validationEAAQualification.getValidationPIDQualificationProcess();
        assertNotNull(pidQualificationProcess);
        assertEquals(Indication.FAILED, pidQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, pidQualificationProcess.getEAAQualification());

        boolean loteReachedCheckFound = false;
        boolean pidDocumentTypeCheckFound = false;
        boolean loteAcceptableCheckFound = false;
        boolean loteTypeForPIDProvidersCheckFound = false;
        boolean acceptableLoTEFoundCheckFound = false;
        boolean certForPIDIssuanceCheckFound = false;
        boolean certForPIDIssuanceAtIssuanceTimeCheckFound = false;
        boolean certForPIDIssuanceAtValidationTimeCheckFound = false;
        for (XmlConstraint xmlConstraint : pidQualificationProcess.getConstraint()) {
            if (MessageTag.EAA_CERT_LOTE_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_CERT_LOTE_REACHED_ANS.getId(), xmlConstraint.getError().getKey());
                loteReachedCheckFound = true;
            } else if (MessageTag.PID_DOCUMENT_TYPE.getId().equals(xmlConstraint.getName().getKey())) {
                pidDocumentTypeCheckFound = true;
            } else if (MessageTag.CERT_USAGE_LOTE_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                loteAcceptableCheckFound = true;
            } else if (MessageTag.PID_LOTE_TYPE_PID_PROVIDERS.getId().equals(xmlConstraint.getName().getKey())) {
                loteTypeForPIDProvidersCheckFound = true;
            } else if (MessageTag.CERT_USAGE_VALID_LOTE_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                acceptableLoTEFoundCheckFound = true;
            } else if (MessageTag.PID_STI_PID_ISSUANCE.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_ISSUANCE_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtIssuanceTimeCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_VALIDATION_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtValidationTimeCheckFound = true;
            }
        }
        assertTrue(loteReachedCheckFound);
        assertFalse(pidDocumentTypeCheckFound);
        assertFalse(loteAcceptableCheckFound);
        assertFalse(loteTypeForPIDProvidersCheckFound);
        assertFalse(acceptableLoTEFoundCheckFound);
        assertFalse(certForPIDIssuanceCheckFound);
        assertFalse(certForPIDIssuanceAtIssuanceTimeCheckFound);
        assertFalse(certForPIDIssuanceAtValidationTimeCheckFound);

        checkReports(reports);
    }

    @Test
    void noPIDTypeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_pid.xml"));
        assertNotNull(diagnosticData);

        eu.europa.esig.dss.diagnostic.jaxb.XmlEAA eaa = diagnosticData.getEAAs().get(0);
        eaa.getEAAPayload().getVerifiableCredentialsType().setText("urn:none:eu:pid:1");

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(loadDefaultPolicy());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(AttestationQualification.NA, simpleReport.getEAAQualification(simpleReport.getFirstEAAId()));
        assertEquals(Collections.singletonList(AttestationQualification.NA), simpleReport.getEAAQualifications(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.EAA_QUAL_CONCLUSIVE_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.PID_DOCUMENT_TYPE_ANS, "urn:none:eu:pid:1")));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Collections.singletonList(AttestationQualification.NA), detailedReport.getEAAQualifications(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                sigValidationConclusiveCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        boolean sigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                sigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);

        XmlValidationEAAQualification validationEAAQualification = xmlEAA.getValidationEAAQualification();
        assertNotNull(validationEAAQualification);
        assertEquals(Indication.FAILED, validationEAAQualification.getConclusion().getIndication());

        boolean trustAnchorListCheckFound = false;
        boolean eaaQualConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationEAAQualification.getConstraint()) {
            if (MessageTag.EAA_CERT_TRUST_ANCHOR_LIST_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                trustAnchorListCheckFound = true;
            } else if (MessageTag.EAA_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                eaaQualConclusiveCheckFound = true;
            }
        }
        assertTrue(trustAnchorListCheckFound);
        assertTrue(eaaQualConclusiveCheckFound);

        XmlValidationEAAQualificationProcess eaaQualificationProcess = validationEAAQualification.getValidationEAAQualificationProcess();
        assertNotNull(eaaQualificationProcess);
        assertEquals(Indication.FAILED, eaaQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, eaaQualificationProcess.getEAAQualification());

        XmlValidationPIDQualificationProcess pidQualificationProcess = validationEAAQualification.getValidationPIDQualificationProcess();
        assertNotNull(pidQualificationProcess);
        assertEquals(Indication.FAILED, pidQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, pidQualificationProcess.getEAAQualification());

        boolean loteReachedCheckFound = false;
        boolean pidDocumentTypeCheckFound = false;
        boolean loteAcceptableCheckFound = false;
        boolean loteTypeForPIDProvidersCheckFound = false;
        boolean acceptableLoTEFoundCheckFound = false;
        boolean certForPIDIssuanceCheckFound = false;
        boolean certForPIDIssuanceAtIssuanceTimeCheckFound = false;
        boolean certForPIDIssuanceAtValidationTimeCheckFound = false;
        for (XmlConstraint xmlConstraint : pidQualificationProcess.getConstraint()) {
            if (MessageTag.EAA_CERT_LOTE_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteReachedCheckFound = true;
            } else if (MessageTag.PID_DOCUMENT_TYPE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PID_DOCUMENT_TYPE_ANS.getId(), xmlConstraint.getError().getKey());
                pidDocumentTypeCheckFound = true;
            } else if (MessageTag.CERT_USAGE_LOTE_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                loteAcceptableCheckFound = true;
            } else if (MessageTag.PID_LOTE_TYPE_PID_PROVIDERS.getId().equals(xmlConstraint.getName().getKey())) {
                loteTypeForPIDProvidersCheckFound = true;
            } else if (MessageTag.CERT_USAGE_VALID_LOTE_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                acceptableLoTEFoundCheckFound = true;
            } else if (MessageTag.PID_STI_PID_ISSUANCE.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_ISSUANCE_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtIssuanceTimeCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_VALIDATION_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtValidationTimeCheckFound = true;
            }
        }
        assertTrue(loteReachedCheckFound);
        assertTrue(pidDocumentTypeCheckFound);
        assertFalse(loteAcceptableCheckFound);
        assertFalse(loteTypeForPIDProvidersCheckFound);
        assertFalse(acceptableLoTEFoundCheckFound);
        assertFalse(certForPIDIssuanceCheckFound);
        assertFalse(certForPIDIssuanceAtIssuanceTimeCheckFound);
        assertFalse(certForPIDIssuanceAtValidationTimeCheckFound);

        checkReports(reports);
    }

    @Test
    void noAcceptableLoTETest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_pid.xml"));
        assertNotNull(diagnosticData);

        XmlListOfTrustedEntities lote = diagnosticData.getListsOfTrustedEntities().get(0);
        lote.setWellSigned(false);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEIDASConstraints().setLoTEWellSigned(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(AttestationQualification.NA, simpleReport.getEAAQualification(simpleReport.getFirstEAAId()));
        assertEquals(Collections.singletonList(AttestationQualification.NA), simpleReport.getEAAQualifications(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.EAA_QUAL_CONCLUSIVE_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.CERT_USAGE_VALID_LOTE_PRESENT_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.CERT_USAGE_LOTE_ACCEPT_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Collections.singletonList(AttestationQualification.NA), detailedReport.getEAAQualifications(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                sigValidationConclusiveCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        boolean sigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                sigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);

        XmlValidationEAAQualification validationEAAQualification = xmlEAA.getValidationEAAQualification();
        assertNotNull(validationEAAQualification);
        assertEquals(Indication.FAILED, validationEAAQualification.getConclusion().getIndication());

        boolean trustAnchorListCheckFound = false;
        boolean eaaQualConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationEAAQualification.getConstraint()) {
            if (MessageTag.EAA_CERT_TRUST_ANCHOR_LIST_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                trustAnchorListCheckFound = true;
            } else if (MessageTag.EAA_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                eaaQualConclusiveCheckFound = true;
            }
        }
        assertTrue(trustAnchorListCheckFound);
        assertTrue(eaaQualConclusiveCheckFound);

        XmlValidationEAAQualificationProcess eaaQualificationProcess = validationEAAQualification.getValidationEAAQualificationProcess();
        assertNotNull(eaaQualificationProcess);
        assertEquals(Indication.FAILED, eaaQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, eaaQualificationProcess.getEAAQualification());

        XmlValidationPIDQualificationProcess pidQualificationProcess = validationEAAQualification.getValidationPIDQualificationProcess();
        assertNotNull(pidQualificationProcess);
        assertEquals(Indication.FAILED, pidQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, pidQualificationProcess.getEAAQualification());

        boolean loteReachedCheckFound = false;
        boolean pidDocumentTypeCheckFound = false;
        boolean loteAcceptableCheckFound = false;
        boolean loteTypeForPIDProvidersCheckFound = false;
        boolean acceptableLoTEFoundCheckFound = false;
        boolean certForPIDIssuanceCheckFound = false;
        boolean certForPIDIssuanceAtIssuanceTimeCheckFound = false;
        boolean certForPIDIssuanceAtValidationTimeCheckFound = false;
        for (XmlConstraint xmlConstraint : pidQualificationProcess.getConstraint()) {
            if (MessageTag.EAA_CERT_LOTE_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteReachedCheckFound = true;
            } else if (MessageTag.PID_DOCUMENT_TYPE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                pidDocumentTypeCheckFound = true;
            } else if (MessageTag.CERT_USAGE_LOTE_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.CERT_USAGE_LOTE_ACCEPT_ANS.getId(), xmlConstraint.getWarning().getKey());
                loteAcceptableCheckFound = true;
            } else if (MessageTag.PID_LOTE_TYPE_PID_PROVIDERS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteTypeForPIDProvidersCheckFound = true;
            } else if (MessageTag.CERT_USAGE_VALID_LOTE_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.CERT_USAGE_VALID_LOTE_PRESENT_ANS.getId(), xmlConstraint.getError().getKey());
                acceptableLoTEFoundCheckFound = true;
            } else if (MessageTag.PID_STI_PID_ISSUANCE.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_ISSUANCE_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtIssuanceTimeCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_VALIDATION_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtValidationTimeCheckFound = true;
            }
        }
        assertTrue(loteReachedCheckFound);
        assertTrue(pidDocumentTypeCheckFound);
        assertTrue(loteAcceptableCheckFound);
        assertTrue(loteTypeForPIDProvidersCheckFound);
        assertTrue(acceptableLoTEFoundCheckFound);
        assertFalse(certForPIDIssuanceCheckFound);
        assertFalse(certForPIDIssuanceAtIssuanceTimeCheckFound);
        assertFalse(certForPIDIssuanceAtValidationTimeCheckFound);

        checkReports(reports);
    }

    @Test
    void noPIDLoTETest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_pid.xml"));
        assertNotNull(diagnosticData);

        XmlListOfTrustedEntities lote = diagnosticData.getListsOfTrustedEntities().get(0);
        lote.setType(LoTETypeEnum.EUWalletProvidersList.getUri());

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEIDASConstraints().setLoTEWellSigned(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(AttestationQualification.NA, simpleReport.getEAAQualification(simpleReport.getFirstEAAId()));
        assertEquals(Collections.singletonList(AttestationQualification.NA), simpleReport.getEAAQualifications(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.EAA_QUAL_CONCLUSIVE_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.CERT_USAGE_VALID_LOTE_PRESENT_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.PID_LOTE_TYPE_PID_PROVIDERS_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Collections.singletonList(AttestationQualification.NA), detailedReport.getEAAQualifications(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                sigValidationConclusiveCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        boolean sigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                sigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);

        XmlValidationEAAQualification validationEAAQualification = xmlEAA.getValidationEAAQualification();
        assertNotNull(validationEAAQualification);
        assertEquals(Indication.FAILED, validationEAAQualification.getConclusion().getIndication());

        boolean trustAnchorListCheckFound = false;
        boolean eaaQualConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationEAAQualification.getConstraint()) {
            if (MessageTag.EAA_CERT_TRUST_ANCHOR_LIST_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                trustAnchorListCheckFound = true;
            } else if (MessageTag.EAA_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                eaaQualConclusiveCheckFound = true;
            }
        }
        assertTrue(trustAnchorListCheckFound);
        assertTrue(eaaQualConclusiveCheckFound);

        XmlValidationEAAQualificationProcess eaaQualificationProcess = validationEAAQualification.getValidationEAAQualificationProcess();
        assertNotNull(eaaQualificationProcess);
        assertEquals(Indication.FAILED, eaaQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, eaaQualificationProcess.getEAAQualification());

        XmlValidationPIDQualificationProcess pidQualificationProcess = validationEAAQualification.getValidationPIDQualificationProcess();
        assertNotNull(pidQualificationProcess);
        assertEquals(Indication.FAILED, pidQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, pidQualificationProcess.getEAAQualification());

        boolean loteReachedCheckFound = false;
        boolean pidDocumentTypeCheckFound = false;
        boolean loteAcceptableCheckFound = false;
        boolean loteTypeForPIDProvidersCheckFound = false;
        boolean acceptableLoTEFoundCheckFound = false;
        boolean certForPIDIssuanceCheckFound = false;
        boolean certForPIDIssuanceAtIssuanceTimeCheckFound = false;
        boolean certForPIDIssuanceAtValidationTimeCheckFound = false;
        for (XmlConstraint xmlConstraint : pidQualificationProcess.getConstraint()) {
            if (MessageTag.EAA_CERT_LOTE_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteReachedCheckFound = true;
            } else if (MessageTag.PID_DOCUMENT_TYPE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                pidDocumentTypeCheckFound = true;
            } else if (MessageTag.CERT_USAGE_LOTE_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteAcceptableCheckFound = true;
            } else if (MessageTag.PID_LOTE_TYPE_PID_PROVIDERS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.PID_LOTE_TYPE_PID_PROVIDERS_ANS.getId(), xmlConstraint.getWarning().getKey());
                loteTypeForPIDProvidersCheckFound = true;
            } else if (MessageTag.CERT_USAGE_VALID_LOTE_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.CERT_USAGE_VALID_LOTE_PRESENT_ANS.getId(), xmlConstraint.getError().getKey());
                acceptableLoTEFoundCheckFound = true;
            } else if (MessageTag.PID_STI_PID_ISSUANCE.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_ISSUANCE_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtIssuanceTimeCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_VALIDATION_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtValidationTimeCheckFound = true;
            }
        }
        assertTrue(loteReachedCheckFound);
        assertTrue(pidDocumentTypeCheckFound);
        assertTrue(loteAcceptableCheckFound);
        assertTrue(loteTypeForPIDProvidersCheckFound);
        assertTrue(acceptableLoTEFoundCheckFound);
        assertFalse(certForPIDIssuanceCheckFound);
        assertFalse(certForPIDIssuanceAtIssuanceTimeCheckFound);
        assertFalse(certForPIDIssuanceAtValidationTimeCheckFound);

        checkReports(reports);
    }

    @Test
    void noPIDIssuanceTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_pid.xml"));
        assertNotNull(diagnosticData);

        XmlSigningCertificate signingCertificate = diagnosticData.getEAAs().get(0)
                .getEAASignature().get(0).getSignature().getSigningCertificate();
        List<XmlTrustedEntity> trustedEntities = signingCertificate.getCertificate().getTrustedEntities();
        trustedEntities.get(0).getTrustedEntityServices().get(0).setServiceType(LoTEServiceTypeIdentifierEnum.PID_REVOCATION.getUri());

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEIDASConstraints().setLoTEWellSigned(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(AttestationQualification.UNKNOWN, simpleReport.getEAAQualification(simpleReport.getFirstEAAId()));
        assertEquals(Collections.singletonList(AttestationQualification.UNKNOWN), simpleReport.getEAAQualifications(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.EAA_QUAL_CONCLUSIVE_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.PID_STI_PID_ISSUANCE_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstEAAId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Collections.singletonList(AttestationQualification.UNKNOWN), detailedReport.getEAAQualifications(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                sigValidationConclusiveCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        boolean sigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                sigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);

        XmlValidationEAAQualification validationEAAQualification = xmlEAA.getValidationEAAQualification();
        assertNotNull(validationEAAQualification);
        assertEquals(Indication.FAILED, validationEAAQualification.getConclusion().getIndication());

        boolean trustAnchorListCheckFound = false;
        boolean eaaQualConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationEAAQualification.getConstraint()) {
            if (MessageTag.EAA_CERT_TRUST_ANCHOR_LIST_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                trustAnchorListCheckFound = true;
            } else if (MessageTag.EAA_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                eaaQualConclusiveCheckFound = true;
            }
        }
        assertTrue(trustAnchorListCheckFound);
        assertTrue(eaaQualConclusiveCheckFound);

        XmlValidationEAAQualificationProcess eaaQualificationProcess = validationEAAQualification.getValidationEAAQualificationProcess();
        assertNotNull(eaaQualificationProcess);
        assertEquals(Indication.FAILED, eaaQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, eaaQualificationProcess.getEAAQualification());

        XmlValidationPIDQualificationProcess pidQualificationProcess = validationEAAQualification.getValidationPIDQualificationProcess();
        assertNotNull(pidQualificationProcess);
        assertEquals(Indication.FAILED, pidQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.UNKNOWN, pidQualificationProcess.getEAAQualification());

        boolean loteReachedCheckFound = false;
        boolean pidDocumentTypeCheckFound = false;
        boolean loteAcceptableCheckFound = false;
        boolean loteTypeForPIDProvidersCheckFound = false;
        boolean acceptableLoTEFoundCheckFound = false;
        boolean certForPIDIssuanceCheckFound = false;
        boolean certForPIDIssuanceAtIssuanceTimeCheckFound = false;
        boolean certForPIDIssuanceAtValidationTimeCheckFound = false;
        for (XmlConstraint xmlConstraint : pidQualificationProcess.getConstraint()) {
            if (MessageTag.EAA_CERT_LOTE_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteReachedCheckFound = true;
            } else if (MessageTag.PID_DOCUMENT_TYPE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                pidDocumentTypeCheckFound = true;
            } else if (MessageTag.CERT_USAGE_LOTE_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteAcceptableCheckFound = true;
            } else if (MessageTag.PID_LOTE_TYPE_PID_PROVIDERS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteTypeForPIDProvidersCheckFound = true;
            } else if (MessageTag.CERT_USAGE_VALID_LOTE_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                acceptableLoTEFoundCheckFound = true;
            } else if (MessageTag.PID_STI_PID_ISSUANCE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PID_STI_PID_ISSUANCE_ANS.getId(), xmlConstraint.getError().getKey());
                certForPIDIssuanceCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_ISSUANCE_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtIssuanceTimeCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_VALIDATION_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtValidationTimeCheckFound = true;
            }
        }
        assertTrue(loteReachedCheckFound);
        assertTrue(pidDocumentTypeCheckFound);
        assertTrue(loteAcceptableCheckFound);
        assertTrue(loteTypeForPIDProvidersCheckFound);
        assertTrue(acceptableLoTEFoundCheckFound);
        assertTrue(certForPIDIssuanceCheckFound);
        assertFalse(certForPIDIssuanceAtIssuanceTimeCheckFound);
        assertFalse(certForPIDIssuanceAtValidationTimeCheckFound);

        checkReports(reports);
    }

    @Test
    void noPIDProviderAtTimeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_pid.xml"));
        assertNotNull(diagnosticData);

        XmlSigningCertificate signingCertificate = diagnosticData.getEAAs().get(0)
                .getEAASignature().get(0).getSignature().getSigningCertificate();
        List<XmlTrustedEntity> trustedEntities = signingCertificate.getCertificate().getTrustedEntities();
        trustedEntities.get(0).getTrustedEntityServices().get(0).setStatus("unknown");

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEIDASConstraints().setLoTEWellSigned(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(AttestationQualification.UNKNOWN, simpleReport.getEAAQualification(simpleReport.getFirstEAAId()));
        assertEquals(Collections.singletonList(AttestationQualification.UNKNOWN), simpleReport.getEAAQualifications(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.EAA_QUAL_CONCLUSIVE_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.PID_PROVIDER_AT_ISSUANCE_TIME_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstEAAId()),
                i18nProvider.getMessage(MessageTag.CERT_USAGE_STATUS_KNOWN_ANS)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfo(simpleReport.getFirstEAAId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Collections.singletonList(AttestationQualification.UNKNOWN), detailedReport.getEAAQualifications(simpleReport.getFirstEAAId()));

        XmlEAA xmlEAA = detailedReport.getXmlEAAById(detailedReport.getFirstEAAId());
        assertNotNull(xmlEAA);

        XmlValidationProcessEAA validationProcessEAA = xmlEAA.getValidationProcessEAA();
        assertNotNull(validationProcessEAA);
        assertEquals(Indication.PASSED, validationProcessEAA.getConclusion().getIndication());

        boolean fcCheckFound = false;
        boolean sigValidationConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessEAA.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BSV_IFCRC.getId().equals(xmlConstraint.getName().getKey())) {
                fcCheckFound = true;
            } else if (MessageTag.ADEST_IBSVPSC.getId().equals(xmlConstraint.getName().getKey())) {
                sigValidationConclusiveCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);
        assertTrue(sigValidationConclusiveCheckFound);

        XmlBasicBuildingBlocks eaaBBB = detailedReport.getBasicBuildingBlockById(xmlEAA.getId());
        assertNotNull(eaaBBB);

        XmlFC xmlFC = eaaBBB.getFC();
        assertNotNull(xmlFC);

        boolean sigPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlFC.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.EAA_SIG_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                sigPresentCheckFound = true;
            }
        }
        assertTrue(sigPresentCheckFound);

        XmlValidationEAAQualification validationEAAQualification = xmlEAA.getValidationEAAQualification();
        assertNotNull(validationEAAQualification);
        assertEquals(Indication.FAILED, validationEAAQualification.getConclusion().getIndication());

        boolean trustAnchorListCheckFound = false;
        boolean eaaQualConclusiveCheckFound = false;
        for (XmlConstraint xmlConstraint : validationEAAQualification.getConstraint()) {
            if (MessageTag.EAA_CERT_TRUST_ANCHOR_LIST_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                trustAnchorListCheckFound = true;
            } else if (MessageTag.EAA_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                eaaQualConclusiveCheckFound = true;
            }
        }
        assertTrue(trustAnchorListCheckFound);
        assertTrue(eaaQualConclusiveCheckFound);

        XmlValidationEAAQualificationProcess eaaQualificationProcess = validationEAAQualification.getValidationEAAQualificationProcess();
        assertNotNull(eaaQualificationProcess);
        assertEquals(Indication.FAILED, eaaQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.NA, eaaQualificationProcess.getEAAQualification());

        XmlValidationPIDQualificationProcess pidQualificationProcess = validationEAAQualification.getValidationPIDQualificationProcess();
        assertNotNull(pidQualificationProcess);
        assertEquals(Indication.FAILED, pidQualificationProcess.getConclusion().getIndication());
        assertEquals(AttestationQualification.UNKNOWN, pidQualificationProcess.getEAAQualification());

        boolean loteReachedCheckFound = false;
        boolean pidDocumentTypeCheckFound = false;
        boolean loteAcceptableCheckFound = false;
        boolean loteTypeForPIDProvidersCheckFound = false;
        boolean acceptableLoTEFoundCheckFound = false;
        boolean certForPIDIssuanceCheckFound = false;
        boolean certForPIDIssuanceAtIssuanceTimeCheckFound = false;
        boolean certForPIDIssuanceAtValidationTimeCheckFound = false;
        for (XmlConstraint xmlConstraint : pidQualificationProcess.getConstraint()) {
            if (MessageTag.EAA_CERT_LOTE_REACHED.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteReachedCheckFound = true;
            } else if (MessageTag.PID_DOCUMENT_TYPE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                pidDocumentTypeCheckFound = true;
            } else if (MessageTag.CERT_USAGE_LOTE_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteAcceptableCheckFound = true;
            } else if (MessageTag.PID_LOTE_TYPE_PID_PROVIDERS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                loteTypeForPIDProvidersCheckFound = true;
            } else if (MessageTag.CERT_USAGE_VALID_LOTE_PRESENT.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                acceptableLoTEFoundCheckFound = true;
            } else if (MessageTag.PID_STI_PID_ISSUANCE.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                certForPIDIssuanceCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_ISSUANCE_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PID_PROVIDER_AT_ISSUANCE_TIME_ANS.getId(), xmlConstraint.getError().getKey());
                certForPIDIssuanceAtIssuanceTimeCheckFound = true;
            } else if (MessageTag.PID_PROVIDER_AT_VALIDATION_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                certForPIDIssuanceAtValidationTimeCheckFound = true;
            }
        }
        assertTrue(loteReachedCheckFound);
        assertTrue(pidDocumentTypeCheckFound);
        assertTrue(loteAcceptableCheckFound);
        assertTrue(loteTypeForPIDProvidersCheckFound);
        assertTrue(acceptableLoTEFoundCheckFound);
        assertTrue(certForPIDIssuanceCheckFound);
        assertTrue(certForPIDIssuanceAtIssuanceTimeCheckFound);
        assertFalse(certForPIDIssuanceAtValidationTimeCheckFound);

        checkReports(reports);
    }

    @Override
    protected EtsiValidationPolicy loadDefaultPolicy() throws Exception {
        return (EtsiValidationPolicy) ValidationPolicyLoader.fromValidationPolicy(PID_POLICY_LOCATION).create();
    }

}
