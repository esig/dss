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
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAARevocationStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAARevocationToken;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.attestation.AttestationProcessExecutor;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Calendar;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttestationRevocationValidationProcessExecutorTest extends AbstractTestValidationExecutor {

    private static final String EAA_POLICY_LOCATION = "/policy/eaa-constraint.xml";

    private static I18nProvider i18nProvider;

    @BeforeAll
    static void init() {
        i18nProvider = new I18nProvider(Locale.getDefault());
    }

    @Test
    void statusUnknownTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        xmlEAARevocationStatus.setStatus(AttestationStatus.UNKNOWN);

        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getEAAConstraints().setEAARevocationPresent(levelConstraint);
        validationPolicy.getEAAConstraints().setEAARevocationAvailable(levelConstraint);
        validationPolicy.getEAAConstraints().setAcceptableEAARevocationFound(levelConstraint);
        validationPolicy.getEAAConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getEAAConstraints().setNotOnHold(levelConstraint);

        validationPolicy.getEAARevocationConstraints().setUnknownStatus(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEAAId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_KNOWN_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_KNOWN_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_KNOWN_ANS.getId(), xmlConstraint.getError().getKey());
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
        assertTrue(unknownCheckFound);
        assertFalse(acceptableStatusCheckFound);
        assertFalse(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(eaaRevocationBBB.getVCI());

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

        checkReports(reports);
    }

    @Test
    void statusIssuanceFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();
        eaaRevocationToken.setIssuedAt(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getEAARevocationConstraints().setIssuanceTime(levelConstraint);

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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_ACC_FND_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean issTimeCheckFound = false;
        boolean expTimeCheckFound = false;
        boolean notExpiredCheckFound = false;
        boolean subjectCheckFound = false;
        boolean subjectMatchCheckFound = false;
        boolean eaaRevocationIssuerCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.EAA_REV_ISS.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_ISS_ANS.getId(), xmlConstraint.getError().getKey());
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
        assertFalse(expTimeCheckFound);
        assertFalse(notExpiredCheckFound);
        assertFalse(subjectCheckFound);
        assertFalse(subjectMatchCheckFound);
        assertFalse(eaaRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusIssuanceWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();
        eaaRevocationToken.setIssuedAt(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);

        validationPolicy.getEAARevocationConstraints().setIssuanceTime(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusAvailableCheckFound = true;
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
        assertTrue(unknownCheckFound);
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
        assertNull(eaaRevocationBBB.getVCI());

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_ISS_ANS.getId(), xmlConstraint.getWarning().getKey());
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
        assertFalse(eaaRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusExpirationFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();
        eaaRevocationToken.setExpirationTime(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEAARevocationConstraints().setExpirationTime(levelConstraint);

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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_EXP_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_ACC_FND_ANS)));
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_EXP_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_EXP_ANS)));

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
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_EXP_ANS.getId(), xmlConstraint.getError().getKey());
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
        assertFalse(notExpiredCheckFound);
        assertFalse(subjectCheckFound);
        assertFalse(subjectMatchCheckFound);
        assertFalse(eaaRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusExpirationWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();
        eaaRevocationToken.setExpirationTime(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);

        validationPolicy.getEAARevocationConstraints().setExpirationTime(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_EXP_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_EXP_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusAvailableCheckFound = true;
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
        assertTrue(unknownCheckFound);
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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_EXP_ANS)));

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_EXP_ANS.getId(), xmlConstraint.getWarning().getKey());
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
        assertFalse(notExpiredCheckFound);
        assertTrue(subjectCheckFound);
        assertTrue(subjectMatchCheckFound);
        assertTrue(eaaRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusExpiredFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(diagnosticData.getValidationDate());
        calendar.add(Calendar.HOUR, -1);
        eaaRevocationToken.setExpirationTime(calendar.getTime());

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEAARevocationConstraints().setNotExpired(levelConstraint);

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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_EXP_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_ACC_FND_ANS)));
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_EXP_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_EXP_ANS)));

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
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_NOT_EXP_ANS.getId(), xmlConstraint.getError().getKey());
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
        assertFalse(subjectCheckFound);
        assertFalse(subjectMatchCheckFound);
        assertFalse(eaaRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusNotExpiredWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(diagnosticData.getValidationDate());
        calendar.add(Calendar.HOUR, -1);
        eaaRevocationToken.setExpirationTime(calendar.getTime());

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);

        validationPolicy.getEAARevocationConstraints().setNotExpired(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_EXP_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_EXP_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusAvailableCheckFound = true;
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
        assertTrue(unknownCheckFound);
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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_EXP_ANS)));

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_NOT_EXP_ANS.getId(), xmlConstraint.getWarning().getKey());
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

        checkReports(reports);
    }

    @Test
    void statusSubjectFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();

        eaaRevocationToken.setSubject(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
        levelConstraint.getId().add("*");
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEAARevocationConstraints().setSubject(levelConstraint);

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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_ACC_FND_ANS)));
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_ANS)));

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
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
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
        assertFalse(subjectMatchCheckFound);
        assertFalse(eaaRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusSubjectWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();

        eaaRevocationToken.setSubject(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
        levelConstraint.getId().add("*");
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getEAARevocationConstraints().setSubject(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusAvailableCheckFound = true;
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
        assertTrue(unknownCheckFound);
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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_ANS)));

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_SUB_ANS.getId(), xmlConstraint.getWarning().getKey());
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
        assertFalse(subjectMatchCheckFound);
        assertTrue(eaaRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusSubjectNoMatchFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();

        eaaRevocationToken.getSubject().setMatch(false);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEAARevocationConstraints().setSubjectMatch(levelConstraint);

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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_MATCH_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_ACC_FND_ANS)));
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_MATCH_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_MATCH_ANS)));

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
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_SUB_MATCH_ANS.getId(), xmlConstraint.getError().getKey());
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
        assertFalse(eaaRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusSubjectNoMatchWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();

        eaaRevocationToken.getSubject().setMatch(false);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getEAARevocationConstraints().setSubjectMatch(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_MATCH_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_MATCH_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusAvailableCheckFound = true;
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
        assertTrue(unknownCheckFound);
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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_MATCH_ANS)));

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_SUB_MATCH_ANS.getId(), xmlConstraint.getWarning().getKey());
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

        checkReports(reports);
    }

    @Test
    void statusIssCertValidFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(eaaRevocationToken.getSigningCertificate().getCertificate().getNotBefore());
        calendar.add(Calendar.DATE, -1);
        eaaRevocationToken.setIssuedAt(calendar.getTime());

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getEAARevocationConstraints().setIssuerValidAtIssuanceTime(levelConstraint);

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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_VALID_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_ACC_FND_ANS)));
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_VALID_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.EAA_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_VALID_ANS)));

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
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_ISS_VALID_ANS.getId(), xmlConstraint.getError().getKey());
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

        checkReports(reports);
    }

    @Test
    void statusIssCertValidWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/attestation-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlEAARevocationStatus xmlEAARevocationStatus = diagnosticData.getEAAs().get(0).getAttestationRevocations().get(0);
        XmlEAARevocationToken eaaRevocationToken = xmlEAARevocationStatus.getEAARevocationToken();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(eaaRevocationToken.getSigningCertificate().getCertificate().getNotBefore());
        calendar.add(Calendar.DATE, -1);
        eaaRevocationToken.setIssuedAt(calendar.getTime());

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getEAARevocationConstraints().setIssuerValidAtIssuanceTime(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstEAAId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstEAAId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstEAAId()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_VALID_ANS)));
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
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_VALID_ANS)));

        boolean statusPresentCheckFound = false;
        boolean statusAvailableCheckFound = false;
        boolean unknownCheckFound = false;
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
                unknownCheckFound = true;
            } else if (MessageTag.EAA_REV_KNOWN.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                statusAvailableCheckFound = true;
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
        assertTrue(unknownCheckFound);
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
        assertNull(eaaRevocationBBB.getVCI());

        xmlSAV = eaaRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_VALID_ANS)));

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_ISS_VALID_ANS.getId(), xmlConstraint.getWarning().getKey());
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

        checkReports(reports);
    }

    @Override
    protected EtsiValidationPolicy loadDefaultPolicy() throws Exception {
        return (EtsiValidationPolicy) ValidationPolicyLoader.fromValidationPolicy(EAA_POLICY_LOCATION).create();
    }

}
