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
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationRevocationStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationRevocationToken;
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
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        xmlAttestationRevocationStatus.setStatus(AttestationStatus.UNKNOWN);

        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getAttestationConstraints().setRevocationPresent(levelConstraint);
        validationPolicy.getAttestationConstraints().setRevocationAvailable(levelConstraint);
        validationPolicy.getAttestationConstraints().setAcceptableRevocationFound(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotRevoked(levelConstraint);
        validationPolicy.getAttestationConstraints().setNotOnHold(levelConstraint);

        validationPolicy.getAttestationRevocationConstraints().setUnknownStatus(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstAttestationId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_KNOWN_ANS)));
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
        assertTrue(unknownCheckFound);
        assertFalse(acceptableStatusCheckFound);
        assertFalse(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(attestationRevocationBBB.getVCI());

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

        checkReports(reports);
    }

    @Test
    void statusIssuanceFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();
        attestationRevocationToken.setIssuedAt(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        validationPolicy.getAttestationRevocationConstraints().setIssuanceTime(levelConstraint);

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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean issTimeCheckFound = false;
        boolean expTimeCheckFound = false;
        boolean notExpiredCheckFound = false;
        boolean subjectCheckFound = false;
        boolean subjectMatchCheckFound = false;
        boolean attestationRevocationIssuerCheckFound = false;
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
        assertFalse(expTimeCheckFound);
        assertFalse(notExpiredCheckFound);
        assertFalse(subjectCheckFound);
        assertFalse(subjectMatchCheckFound);
        assertFalse(attestationRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusIssuanceWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();
        attestationRevocationToken.setIssuedAt(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);

        validationPolicy.getAttestationRevocationConstraints().setIssuanceTime(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_ANS)));
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
        assertTrue(unknownCheckFound);
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
        assertNull(attestationRevocationBBB.getVCI());

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
        assertFalse(attestationRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusExpirationFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();
        attestationRevocationToken.setExpirationTime(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getAttestationRevocationConstraints().setExpirationTime(levelConstraint);

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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_EXP_ANS)));
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_EXP_ANS)));

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
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_EXP_ANS.getId(), xmlConstraint.getError().getKey());
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
        assertFalse(notExpiredCheckFound);
        assertFalse(subjectCheckFound);
        assertFalse(subjectMatchCheckFound);
        assertFalse(attestationRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusExpirationWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();
        attestationRevocationToken.setExpirationTime(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);

        validationPolicy.getAttestationRevocationConstraints().setExpirationTime(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_EXP_ANS)));
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
        assertTrue(unknownCheckFound);
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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_EXP_ANS)));

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_EXP_ANS.getId(), xmlConstraint.getWarning().getKey());
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
        assertFalse(notExpiredCheckFound);
        assertTrue(subjectCheckFound);
        assertTrue(subjectMatchCheckFound);
        assertTrue(attestationRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusExpiredFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(diagnosticData.getValidationDate());
        calendar.add(Calendar.HOUR, -1);
        attestationRevocationToken.setExpirationTime(calendar.getTime());

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getAttestationRevocationConstraints().setNotExpired(levelConstraint);

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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_EXP_ANS)));
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_EXP_ANS)));

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
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_NOT_EXP_ANS.getId(), xmlConstraint.getError().getKey());
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
        assertFalse(subjectCheckFound);
        assertFalse(subjectMatchCheckFound);
        assertFalse(attestationRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusNotExpiredWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(diagnosticData.getValidationDate());
        calendar.add(Calendar.HOUR, -1);
        attestationRevocationToken.setExpirationTime(calendar.getTime());

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);

        validationPolicy.getAttestationRevocationConstraints().setNotExpired(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_EXP_ANS)));
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
        assertTrue(unknownCheckFound);
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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_NOT_EXP_ANS)));

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_NOT_EXP_ANS.getId(), xmlConstraint.getWarning().getKey());
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

        checkReports(reports);
    }

    @Test
    void statusSubjectFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();

        attestationRevocationToken.setSubject(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
        levelConstraint.getId().add("*");
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getAttestationRevocationConstraints().setSubject(levelConstraint);

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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_ANS)));
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_ANS)));

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
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
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
        assertFalse(subjectMatchCheckFound);
        assertFalse(attestationRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusSubjectWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();

        attestationRevocationToken.setSubject(null);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
        levelConstraint.getId().add("*");
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getAttestationRevocationConstraints().setSubject(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_ANS)));
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
        assertTrue(unknownCheckFound);
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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_ANS)));

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_SUB_ANS.getId(), xmlConstraint.getWarning().getKey());
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
        assertFalse(subjectMatchCheckFound);
        assertTrue(attestationRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusSubjectNoMatchFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();

        attestationRevocationToken.getSubject().setMatch(false);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getAttestationRevocationConstraints().setSubjectMatch(levelConstraint);

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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_MATCH_ANS)));
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_MATCH_ANS)));

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
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_SUB_MATCH_ANS.getId(), xmlConstraint.getError().getKey());
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
        assertFalse(attestationRevocationIssuerCheckFound);

        checkReports(reports);
    }

    @Test
    void statusSubjectNoMatchWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();

        attestationRevocationToken.getSubject().setMatch(false);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getAttestationRevocationConstraints().setSubjectMatch(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_MATCH_ANS)));
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
        assertTrue(unknownCheckFound);
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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_SUB_MATCH_ANS)));

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_SUB_MATCH_ANS.getId(), xmlConstraint.getWarning().getKey());
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

        checkReports(reports);
    }

    @Test
    void statusIssCertValidFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(attestationRevocationToken.getSigningCertificate().getCertificate().getNotBefore());
        calendar.add(Calendar.DATE, -1);
        attestationRevocationToken.setIssuedAt(calendar.getTime());

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getAttestationRevocationConstraints().setIssuerValidAtIssuanceTime(levelConstraint);

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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_VALID_ANS)));
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
        assertTrue(unknownCheckFound);
        assertTrue(acceptableStatusCheckFound);
        assertTrue(acceptableStatusFoundCheckFound);
        assertFalse(notRevokedCheckFound);
        assertFalse(notOnHoldCheckFound);

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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.ATTESTATION_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_VALID_ANS)));

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
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_ISS_VALID_ANS.getId(), xmlConstraint.getError().getKey());
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

        checkReports(reports);
    }

    @Test
    void statusIssCertValidWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/eaa-validation/diag_data_eaa.xml"));
        assertNotNull(diagnosticData);

        XmlAttestationRevocationStatus xmlAttestationRevocationStatus = diagnosticData.getAttestations().get(0).getAttestationRevocations().get(0);
        XmlAttestationRevocationToken attestationRevocationToken = xmlAttestationRevocationStatus.getAttestationRevocationToken();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(attestationRevocationToken.getSigningCertificate().getCertificate().getNotBefore());
        calendar.add(Calendar.DATE, -1);
        attestationRevocationToken.setIssuedAt(calendar.getTime());

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getAttestationRevocationConstraints().setIssuerValidAtIssuanceTime(levelConstraint);

        AttestationProcessExecutor executor = new AttestationProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setCurrentTime(diagnosticData.getValidationDate());
        executor.setValidationPolicy(validationPolicy);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstAttestationId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstAttestationId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstAttestationId()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_VALID_ANS)));
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
        assertTrue(unknownCheckFound);
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
        assertNull(attestationRevocationBBB.getVCI());

        xmlSAV = attestationRevocationBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSAV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.EAA_REV_ISS_VALID_ANS)));

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
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.EAA_REV_ISS_VALID_ANS.getId(), xmlConstraint.getWarning().getKey());
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

        checkReports(reports);
    }

    @Override
    protected EtsiValidationPolicy loadDefaultPolicy() throws Exception {
        return (EtsiValidationPolicy) ValidationPolicyLoader.fromValidationPolicy(EAA_POLICY_LOCATION).create();
    }

}
