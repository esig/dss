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
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.RevocationConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RevocationDataExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void skipRevocationDataValidation() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/it.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadPolicyNoRevoc());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // TODO: Etsi Validation Report

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testArchiveCutOff() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/archiveCutOff.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(2, usedTimestamps.size());
        for (XmlTimestamp xmlTimestamp : usedTimestamps) {
            assertEquals(TimestampQualification.QTSA, detailedReport.getTimestampQualification(xmlTimestamp.getId()));
        }

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredRevocAndNoCheck() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/expiredRevocAndNoCheck.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredRevocAndNoCheckWithCRL() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/expiredOcspWithNoCheckAndCRL.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();
        assertNotNull(reports);

        // Expiration of the OCSP Responder should not change the validation result
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredRevocAndNoCheckWithCRLWarn() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/expiredOcspWithNoCheckAndCRL.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadPolicyCryptoWarn());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();
        assertNotNull(reports);

        // Expiration of the OCSP Responder should not change the validation result
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredRevocAndNoCheckWithCRLAcceptRevocationSha1() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/expiredOcspWithNoCheckAndCRL.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadPolicyRevocSha1OK());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        // Expiration of the OCSP Responder should not change the validation result
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        // cert is not TSA/QTST
        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> timestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(2, timestamps.size());
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : timestamps) {
            assertEquals(1, timestamp.getQualificationDetails().getError().size());
            assertTrue(checkMessageValuePresence(convertMessages(timestamp.getQualificationDetails().getError()),
                    i18nProvider.getMessage(MessageTag.QUAL_HAS_QTST_ANS)));
        }

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void ocspRevocationMessage() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/ocspRevocationMessage.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        Date validationDate = diagnosticData.getValidationDate();
        executor.setCurrentTime(validationDate);

        executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
        Reports reports = executor.execute();

        DetailedReport detailedReport = reports.getDetailedReport();

        // Extract the build block where the verification failed
        XmlBasicBuildingBlocks basicBuildingBlockById = detailedReport.getBasicBuildingBlockById("R-F104CADD12E8C96491EB3F95667AFB7E594162A461F968CE2D488C32E6A18624");

        // Get the Error Message as well as any extra information
        XmlSAV sav = basicBuildingBlockById.getSAV();
        XmlConstraint xmlConstraint = sav.getConstraint().get(0);
        XmlMessage error = xmlConstraint.getError();

        assertEquals(MessageTag.ASCCM_PKSK_ANS.name(), error.getKey());

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId())); // OCSP Cert not found

        executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId())); // OCSP Cert not found

        executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId())); // Crypto for OCSP
        // Cert not found -->
        // No acceptable revocation
    }

    @Test
    void notTrustedOcspTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/lt-level-with-not-trusted-ocsp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void LTAandAIAforTrustAnchor() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/LTAandAIAforTrustAnchor.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.UNKNOWN, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void revocInfoOutOfBoundsTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/revoc-info-out-of-bounds.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
    }

    @Test
    void certNotBeforeAndCRLSameTimeTest() throws Exception {
        // DSS-1932
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/cert-and-revoc-same-time.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void oneFailedRacTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag-data-one-failed-revocation.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlConclusion conclusion = bbb.getConclusion();
        assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
        assertTrue(Utils.isCollectionNotEmpty(conclusion.getErrors()));
        assertFalse(checkMessageValuePresence(convert(conclusion.getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_HAS_CERT_INFO_ANS)));
        assertFalse(checkMessageValuePresence(convert(conclusion.getWarnings()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_HAS_CERT_INFO_ANS)));

        boolean failedRacFound = false;
        XmlXCV xcv = bbb.getXCV();
        for (XmlRAC rac : xcv.getSubXCV().get(0).getCRS().getRAC()) {
            if (Indication.INDETERMINATE.equals(rac.getConclusion().getIndication())) {
                assertFalse(failedRacFound);
                assertTrue(checkMessageValuePresence(convert(rac.getConclusion().getErrors()),
                        i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_HAS_CERT_INFO_ANS)));
                failedRacFound = true;
            }
        }
        assertTrue(failedRacFound);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_HAS_CERT_INFO_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_HAS_CERT_INFO_ANS)));
    }

    @Test
    void failedRacTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag-data-failed-revocation.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        List<XmlRevocation> usedRevocations = diagnosticData.getUsedRevocations();

        Reports reports = executor.execute();

        DetailedReport detailedReport = reports.getDetailedReport();
        for (XmlRevocation xmlRevocation : usedRevocations) {
            assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(xmlRevocation.getId()));
            assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicBuildingBlocksSubIndication(xmlRevocation.getId()));
            assertEquals(2, detailedReport.getAdESValidationErrors(xmlRevocation.getId()).size());
            assertEquals(0, detailedReport.getAdESValidationWarnings(xmlRevocation.getId()).size());
            assertEquals(0, detailedReport.getAdESValidationInfos(xmlRevocation.getId()).size());

            XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(xmlRevocation.getId());
            assertEquals(2, bbb.getConclusion().getErrors().size());
            assertEquals(0, bbb.getConclusion().getWarnings().size());
            assertEquals(0, bbb.getConclusion().getInfos().size());

            XmlXCV xcv = bbb.getXCV();
            assertNotNull(xcv);
            assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
            assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());
            assertEquals(2, xcv.getConclusion().getErrors().size());
            assertEquals(0, xcv.getConclusion().getWarnings().size());
            assertEquals(0, xcv.getConclusion().getInfos().size());

            boolean failedSubXCVFound = false;
            for (XmlSubXCV subXCV : xcv.getSubXCV()){
                if (Indication.INDETERMINATE.equals(subXCV.getConclusion().getIndication())) {
                    assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, subXCV.getConclusion().getSubIndication());
                    assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()),
                            i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                    assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()),
                            i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));
                    failedSubXCVFound = true;
                }
            }
            assertTrue(failedSubXCVFound);

            assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
                    i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
            assertFalse(checkMessageValuePresence(convert(xcv.getConclusion().getWarnings()),
                    i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

            assertTrue(checkMessageValuePresence(detailedReport.getAdESValidationErrors(xmlRevocation.getId()),
                    i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
            assertFalse(checkMessageValuePresence(detailedReport.getAdESValidationWarnings(xmlRevocation.getId()),
                    i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));
        }

        assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(detailedReport.getAdESValidationErrors(detailedReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertFalse(checkMessageValuePresence(detailedReport.getAdESValidationWarnings(detailedReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

        XmlConstraintsConclusion highestConclusion = detailedReport.getHighestConclusion(detailedReport.getFirstSignatureId());
        assertFalse(checkMessageValuePresence(convert(highestConclusion.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ARCH_LTVV_ANS)));
        assertFalse(checkMessageValuePresence(convert(highestConclusion.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertFalse(checkMessageValuePresence(convert(highestConclusion.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

        SimpleReport simpleReport = reports.getSimpleReport();
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ARCH_LTVV_ANS)));
    }

    @Test
    void notYetValidCRLIssuerTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_not_yet_valid_ca.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        RevocationConstraints revocationConstraints = validationPolicy.getRevocationConstraints();
        BasicSignatureConstraints basicSignatureConstraints = revocationConstraints.getBasicSignatureConstraints();
        CertificateConstraints signingCertificateConstraints = basicSignatureConstraints.getSigningCertificate();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.INFORM);
        signingCertificateConstraints.setAcceptableRevocationDataFound(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        assertNotNull(signingCertificate);

        List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
        assertEquals(1, certificateRevocationData.size());

        CertificateWrapper caCertificate = signingCertificate.getSigningCertificate();
        assertNotNull(caCertificate);

        certificateRevocationData = caCertificate.getCertificateRevocationData();
        assertEquals(1, certificateRevocationData.size());
        CertificateRevocationWrapper revocationWrapper = certificateRevocationData.get(0);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        XmlSubXCV subXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, subXCV.getConclusion().getSubIndication());

        subXCV = subXCVs.get(1);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

        List<XmlRAC> rac = subXCV.getCRS().getRAC();
        assertEquals(1, rac.size());

        XmlRAC xmlRAC = rac.get(0);
        assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlRAC.getConclusion().getSubIndication());

        boolean consistencyCheckFound = false;
        for (XmlConstraint constraint : xmlRAC.getConstraint()) {
            if (MessageTag.BBB_XCV_REVOC_AFTER_CERT_NOT_BEFORE.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_REVOC_AFTER_CERT_NOT_BEFORE_ANS.getId(), constraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_INFO,
                                ValidationProcessUtils.getFormattedDate(revocationWrapper.getThisUpdate()),
                                ValidationProcessUtils.getFormattedDate(caCertificate.getNotBefore()),
                                ValidationProcessUtils.getFormattedDate(caCertificate.getNotAfter())),
                        constraint.getAdditionalInfo());
                consistencyCheckFound = true;
            }
        }
        assertTrue(consistencyCheckFound);
    }

    @Test
    void brokenRevocationDataTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_with_broken_revocation.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        XmlSubXCV subXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());
        assertEquals(2, subXCV.getConclusion().getErrors().size());
        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        XmlCRS crs = subXCV.getCRS();
        assertNotNull(crs);
        assertEquals(Indication.INDETERMINATE, crs.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, crs.getConclusion().getSubIndication());
        assertEquals(2, crs.getConclusion().getErrors().size());
        assertTrue(checkMessageValuePresence(convert(crs.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        List<XmlRAC> racs = crs.getRAC();
        assertEquals(1, racs.size());

        XmlRAC rac = racs.get(0);
        assertEquals(Indication.FAILED, rac.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, rac.getConclusion().getSubIndication());
        assertEquals(1, rac.getConclusion().getErrors().size());
        assertTrue(checkMessageValuePresence(convert(rac.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
    }

    @Test
    void brokenRevocationDataWithWarnSigIntactTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_with_broken_revocation.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        RevocationConstraints revocationConstraints = validationPolicy.getRevocationConstraints();
        BasicSignatureConstraints basicSignatureConstraints = revocationConstraints.getBasicSignatureConstraints();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        basicSignatureConstraints.setSignatureIntact(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        XmlSubXCV subXCV = subXCVs.get(0);
        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));

        List<XmlRAC> racs = subXCV.getCRS().getRAC();
        assertEquals(1, racs.size());

        XmlRAC rac = racs.get(0);
        assertEquals(Indication.PASSED, rac.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
    }

    @Test
    void multipleRevocationDataTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_multiple_revocation.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void multipleRevocationDataWithBrokenArcTstTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_multiple_revocation.xml"));
        assertNotNull(xmlDiagnosticData);

        List<XmlTimestamp> usedTimestamps = xmlDiagnosticData.getUsedTimestamps();
        usedTimestamps.get(1).getDigestMatchers().get(0).setDataIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        boolean revocationIssuerPOECheckFound = false;
        boolean usedRevocIssuerPOECheckFound = false;
        boolean failedRevocFound = false;
        boolean validRevocFound = false;

        boolean psvCrsCheckFound = false;

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

        XmlPSV psv = signatureBBB.getPSV();
        assertNotNull(psv);
        for (XmlConstraint constraint : psv.getConstraint()) {
            if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                psvCrsCheckFound = true;

            } else if (MessageTag.PSV_DIURDSCHPVR.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertNull(constraint.getWarning());
                assertEquals(MessageTag.PSV_DIURDSCHPVR_ANS.getId(), constraint.getError().getKey());
                usedRevocIssuerPOECheckFound = true;
            }
        }

        XmlCRS psvcrs = signatureBBB.getPSVCRS();
        assertNotNull(psvcrs);
        for (XmlConstraint crsConstraint : psvcrs.getConstraint()) {
            if (MessageTag.PSV_IPCRIAIDBEDC.getId().equals(crsConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, crsConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPCRIAIDBEDC_ANS.getId(), crsConstraint.getWarning().getKey());
                assertNull(crsConstraint.getError());
                revocationIssuerPOECheckFound = true;

            } else if (MessageTag.ADEST_RORPIIC.getId().equals(crsConstraint.getName().getKey())) {
                if (XmlStatus.WARNING.equals(crsConstraint.getStatus())) {
                    failedRevocFound = true;
                } else if (XmlStatus.OK.equals(crsConstraint.getStatus())) {
                    validRevocFound = true;
                }
            }
        }

        assertTrue(revocationIssuerPOECheckFound);
        assertTrue(usedRevocIssuerPOECheckFound);
        assertTrue(failedRevocFound);
        assertTrue(validRevocFound);
        assertTrue(psvCrsCheckFound);

        assertTrue(checkMessageValuePresence(convert(psvcrs.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.ADEST_RORPIIC_ANS)));

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.PSV_IPCRIAIDBEDC)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.PSV_DIURDSCHPVR)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRCIRI_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_RORPIIC_ANS)));
    }

    @Test
    void multipleRevocationDataWithRevocationIssuerWarnTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_multiple_revocation.xml"));
        assertNotNull(xmlDiagnosticData);

        List<XmlTimestamp> usedTimestamps = xmlDiagnosticData.getUsedTimestamps();
        usedTimestamps.get(1).getDigestMatchers().get(0).setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRCIRI_ANS)));
    }

    @Test
    void expiredSigningCertificateWithExpiredOCSPLTVTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_and_ocsp_expired_ltv.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());

        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, subXCV.getConclusion().getSubIndication());

        boolean signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signCertKnownNotRevokedCheckFound = false;
        signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), xmlConstraint.getError().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertNotExpiredCheckFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);
        assertFalse(signCertNotExpiredCheckFound);

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean psvCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
                psvCheckFound = true;
            }
        }
        assertFalse(psvCheckFound);
    }

    @Test
    void expiredSigningCertificateWithExpiredOCSPWarnLevelLTVTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_and_ocsp_expired_ltv.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());

        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, subXCV.getConclusion().getSubIndication());

        boolean signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signCertKnownNotRevokedCheckFound = false;
        signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), xmlConstraint.getWarning().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertNotExpiredCheckFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean psvCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
                psvCheckFound = true;
            }
        }
        assertFalse(psvCheckFound);
    }

    @Test
    void expiredSigningCertificateWithExpiredOCSPInfoLevelLTVTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_and_ocsp_expired_ltv.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.INFORM);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());

        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, subXCV.getConclusion().getSubIndication());

        boolean signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signCertKnownNotRevokedCheckFound = false;
        signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), xmlConstraint.getInfo().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertNotExpiredCheckFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean psvCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
                psvCheckFound = true;
            }
        }
        assertFalse(psvCheckFound);
    }

    @Test
    void expiredSigningCertificateWithExpiredOCSPIgnoreLevelLTVTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_and_ocsp_expired_ltv.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.IGNORE);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());

        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, subXCV.getConclusion().getSubIndication());

        boolean signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signCertKnownNotRevokedCheckFound = false;
        signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertNotExpiredCheckFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean psvCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
                psvCheckFound = true;
            }
        }
        assertFalse(psvCheckFound);
    }

    @Test
    void expiredSigningCertificateWithExpiredOCSPSkipLTVTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_and_ocsp_expired_ltv.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(null);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());

        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, subXCV.getConclusion().getSubIndication());

        boolean signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signCertKnownNotRevokedCheckFound = false;
        signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertNotExpiredCheckFound = true;
            }
        }
        assertFalse(signCertKnownNotRevokedCheckFound);
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean psvCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
                psvCheckFound = true;
            }
        }
        assertFalse(psvCheckFound);
    }

    @Test
    void expiredSigningCertificateWithExpiredOCSPFailLevelLTATest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_and_ocsp_expired_lta.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.PSV_IPSVC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.PSV_DIURDSCHPVR_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());

        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, subXCV.getConclusion().getSubIndication());

        boolean signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signCertKnownNotRevokedCheckFound = false;
        signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), xmlConstraint.getError().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertNotExpiredCheckFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);
        assertFalse(signCertNotExpiredCheckFound);

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean psvCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
                psvCheckFound = true;
            }
        }
        assertTrue(psvCheckFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertNotNull(psv);
        assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, psv.getConclusion().getSubIndication());

        signCertKnownNotRevokedCheckFound = false;
        for (XmlConstraint xmlConstraint : psv.getConstraint()) {
            if (MessageTag.PSV_DIURDSCHPVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_DIURDSCHPVR_ANS.getId(), xmlConstraint.getError().getKey());
                signCertKnownNotRevokedCheckFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);

        XmlCRS psvcrs = signatureBBB.getPSVCRS();
        assertNotNull(psvcrs);
        assertEquals(Indication.INDETERMINATE, psvcrs.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, psvcrs.getConclusion().getSubIndication());

        signCertKnownNotRevokedCheckFound = false;
        boolean acceptableRevocationFound = false;
        for (XmlConstraint xmlConstraint : psvcrs.getConstraint()) {
            if (MessageTag.PSV_IPCRIAIDBEDC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPCRIAIDBEDC_ANS.getId(), xmlConstraint.getWarning().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), xmlConstraint.getError().getKey());
                acceptableRevocationFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);
        assertTrue(acceptableRevocationFound);
    }

    @Test
    void expiredSigningCertificateWithExpiredOCSPWarnLevelLTATest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_and_ocsp_expired_lta.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.PSV_DIURDSCHPVR_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());

        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, subXCV.getConclusion().getSubIndication());

        boolean signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signCertKnownNotRevokedCheckFound = false;
        signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), xmlConstraint.getError().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.TSV_IBSTBCEC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            }
        }
        assertFalse(signCertKnownNotRevokedCheckFound);
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean psvCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                psvCheckFound = true;
            }
        }
        assertTrue(psvCheckFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertNotNull(psv);
        assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

        for (XmlConstraint xmlConstraint : psv.getConstraint()) {
            if (MessageTag.PSV_DIURDSCHPVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_DIURDSCHPVR_ANS.getId(), xmlConstraint.getWarning().getKey());
                signCertKnownNotRevokedCheckFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);

        XmlCRS psvcrs = signatureBBB.getPSVCRS();
        assertNotNull(psvcrs);
        assertEquals(Indication.INDETERMINATE, psvcrs.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, psvcrs.getConclusion().getSubIndication());

        signCertKnownNotRevokedCheckFound = false;
        boolean acceptableRevocationFound = false;
        for (XmlConstraint xmlConstraint : psvcrs.getConstraint()) {
            if (MessageTag.PSV_IPCRIAIDBEDC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPCRIAIDBEDC_ANS.getId(), xmlConstraint.getWarning().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), xmlConstraint.getError().getKey());
                acceptableRevocationFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);
        assertTrue(acceptableRevocationFound);
    }

    @Test
    void expiredSigningCertificateWithExpiredOCSPInfoLevelLTATest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_and_ocsp_expired_lta.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.INFORM);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.PSV_DIURDSCHPVR_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());

        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, subXCV.getConclusion().getSubIndication());

        boolean signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signCertKnownNotRevokedCheckFound = false;
        signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), xmlConstraint.getError().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.TSV_IBSTBCEC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            }
        }
        assertFalse(signCertKnownNotRevokedCheckFound);
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean psvCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                psvCheckFound = true;
            }
        }
        assertTrue(psvCheckFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertNotNull(psv);
        assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

        for (XmlConstraint xmlConstraint : psv.getConstraint()) {
            if (MessageTag.PSV_DIURDSCHPVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_DIURDSCHPVR_ANS.getId(), xmlConstraint.getInfo().getKey());
                signCertKnownNotRevokedCheckFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);

        XmlCRS psvcrs = signatureBBB.getPSVCRS();
        assertNotNull(psvcrs);
        assertEquals(Indication.INDETERMINATE, psvcrs.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, psvcrs.getConclusion().getSubIndication());

        signCertKnownNotRevokedCheckFound = false;
        boolean acceptableRevocationFound = false;
        for (XmlConstraint xmlConstraint : psvcrs.getConstraint()) {
            if (MessageTag.PSV_IPCRIAIDBEDC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPCRIAIDBEDC_ANS.getId(), xmlConstraint.getWarning().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), xmlConstraint.getError().getKey());
                acceptableRevocationFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);
        assertTrue(acceptableRevocationFound);
    }

    @Test
    void expiredSigningCertificateWithExpiredOCSPIgnoreLevelLTATest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_and_ocsp_expired_lta.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.IGNORE);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());

        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, subXCV.getConclusion().getSubIndication());

        boolean signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signCertKnownNotRevokedCheckFound = false;
        signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), xmlConstraint.getError().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.TSV_IBSTBCEC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            }
        }
        assertFalse(signCertKnownNotRevokedCheckFound);
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean psvCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                psvCheckFound = true;
            }
        }
        assertTrue(psvCheckFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertNotNull(psv);
        assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

        for (XmlConstraint xmlConstraint : psv.getConstraint()) {
            if (MessageTag.PSV_DIURDSCHPVR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                signCertKnownNotRevokedCheckFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);

        XmlCRS psvcrs = signatureBBB.getPSVCRS();
        assertNotNull(psvcrs);
        assertEquals(Indication.INDETERMINATE, psvcrs.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, psvcrs.getConclusion().getSubIndication());

        signCertKnownNotRevokedCheckFound = false;
        boolean acceptableRevocationFound = false;
        for (XmlConstraint xmlConstraint : psvcrs.getConstraint()) {
            if (MessageTag.PSV_IPCRIAIDBEDC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPCRIAIDBEDC_ANS.getId(), xmlConstraint.getWarning().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), xmlConstraint.getError().getKey());
                acceptableRevocationFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);
        assertTrue(acceptableRevocationFound);
    }

    @Test
    void expiredSigningCertificateWithExpiredOCSPSkipLTATest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_and_ocsp_expired_lta.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.IGNORE);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setRevocationIssuerNotExpired(null);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());

        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, subXCV.getConclusion().getSubIndication());

        boolean signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean signCertKnownNotRevokedCheckFound = false;
        signCertNotExpiredCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), xmlConstraint.getError().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.TSV_IBSTBCEC_ANS.getId(), xmlConstraint.getError().getKey());
                signCertNotExpiredCheckFound = true;
            }
        }
        assertFalse(signCertKnownNotRevokedCheckFound);
        assertTrue(signCertNotExpiredCheckFound);

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean psvCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                psvCheckFound = true;
            }
        }
        assertTrue(psvCheckFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertNotNull(psv);
        assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

        for (XmlConstraint xmlConstraint : psv.getConstraint()) {
            if (MessageTag.PSV_DIURDSCHPVR.getId().equals(xmlConstraint.getName().getKey())) {
                signCertKnownNotRevokedCheckFound = true;
            }
        }
        assertFalse(signCertKnownNotRevokedCheckFound);

        XmlCRS psvcrs = signatureBBB.getPSVCRS();
        assertNotNull(psvcrs);
        assertEquals(Indication.INDETERMINATE, psvcrs.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, psvcrs.getConclusion().getSubIndication());

        signCertKnownNotRevokedCheckFound = false;
        boolean acceptableRevocationFound = false;
        for (XmlConstraint xmlConstraint : psvcrs.getConstraint()) {
            if (MessageTag.PSV_IPCRIAIDBEDC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPCRIAIDBEDC_ANS.getId(), xmlConstraint.getWarning().getKey());
                signCertKnownNotRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), xmlConstraint.getError().getKey());
                acceptableRevocationFound = true;
            }
        }
        assertTrue(signCertKnownNotRevokedCheckFound);
        assertTrue(acceptableRevocationFound);
    }

    @Test
    void ojWithExpiredTstRevocationTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/oj-diag-data-with-tsts.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> timestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(3, timestamps.size());

        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : timestamps) {
            assertEquals(Indication.PASSED, timestamp.getIndication());
            assertNull(timestamp.getAdESValidationDetails());
        }

        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> xmlTimestamps = xmlSignature.getTimestamps();

        int validationTimeFailedTimestampCounter = 0;
        int validationTimePassedTimestampCounter = 0;
        for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp timestamp : xmlTimestamps) {
            XmlValidationProcessBasicTimestamp validationProcessTimestamp = timestamp.getValidationProcessBasicTimestamp();
            if (Indication.INDETERMINATE.equals(validationProcessTimestamp.getConclusion().getIndication())) {
                // no revocation issuer validity check is enforced in case of timestamp (default policy)
                assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessTimestamp.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(validationProcessTimestamp.getConclusion().getErrors()),
                        i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                ++validationTimeFailedTimestampCounter;
            } else if (Indication.PASSED.equals(validationProcessTimestamp.getConclusion().getIndication())) {
                ++validationTimePassedTimestampCounter;
            }
        }
        assertEquals(2, validationTimeFailedTimestampCounter);
        assertEquals(1, validationTimePassedTimestampCounter);

    }

    @Test
    void xadesAWithValidInvalidAndInconsistentRevocationDataTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_xades_a_with_two_revocation.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();

        boolean invalidRevocFound = false;
        boolean inconsistentRevocFound = false;
        boolean validRevocFound = false;

        List<XmlCRS> crss = validationProcessLongTermData.getCRS();
        assertEquals(1, crss.size());
        for (XmlConstraint constraint : crss.get(0).getConstraint()) {
            if (MessageTag.ADEST_RORPIIC.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.WARNING.equals(constraint.getStatus())) {
                    invalidRevocFound = true;
                }
            } else if (MessageTag.BBB_XCV_RAC.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.WARNING.equals(constraint.getStatus())) {
                    inconsistentRevocFound = true;
                } else if (XmlStatus.OK.equals(constraint.getStatus())) {
                    validRevocFound = true;
                }
            }
        }

        assertTrue(invalidRevocFound);
        assertTrue(inconsistentRevocFound);
        assertTrue(validRevocFound);
    }

    @Test
    void failedRacWithinRacTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_failed_rac_within_rac.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        List<XmlRAC> racs = xmlSubXCV.getCRS().getRAC();
        assertEquals(4, racs.size());

        boolean validRacFound = false;
        boolean failedRacFound = false;
        boolean racWithAllFailedIssuerRacsFound = false;
        boolean racWithOneFailedIssuerRacFound = false;
        for (XmlRAC rac : racs) {
            if (Indication.PASSED.equals(rac.getConclusion().getIndication())) {
                int invalidRacCounter = 0;
                int validRacCounter = 0;
                if (rac.getCRS() != null) {
                    for (XmlRAC subRac : rac.getCRS().getRAC()) {
                        if (Indication.PASSED.equals(subRac.getConclusion().getIndication())) {
                            ++validRacCounter;
                        } else {
                            ++invalidRacCounter;
                        }
                    }
                }
                if (validRacCounter == 0 && invalidRacCounter == 0) {
                    validRacFound = true;
                }
                if (validRacCounter > 0 && invalidRacCounter > 0) {
                    assertFalse(checkMessageValuePresence(convert(rac.getConclusion().getWarnings()),
                            i18nProvider.getMessage(MessageTag.BBB_XCV_RAC_ANS)));

                    racWithOneFailedIssuerRacFound = true;
                }

            } else if (Indication.INDETERMINATE.equals(rac.getConclusion().getIndication())) {
                int invalidRacCounter = 0;
                int validRacCounter = 0;
                if (rac.getCRS() != null) {
                    for (XmlRAC subRac : rac.getCRS().getRAC()) {
                        if (Indication.PASSED.equals(subRac.getConclusion().getIndication())) {
                            ++validRacCounter;
                        } else {
                            ++invalidRacCounter;
                        }
                    }
                }
                if (invalidRacCounter != 0 && validRacCounter == 0) {
                    assertTrue(checkMessageValuePresence(convert(rac.getConclusion().getWarnings()),
                            i18nProvider.getMessage(MessageTag.BBB_XCV_RAC_ANS)));
                    racWithAllFailedIssuerRacsFound = true;
                }

            } else if (Indication.FAILED.equals(rac.getConclusion().getIndication())) {
                int racCounter = 0;
                for (XmlConstraint constraint : rac.getConstraint()) {
                    if (MessageTag.BBB_XCV_RAC.getId().equals(constraint.getName().getKey())) {
                        ++racCounter;
                    }
                }
                if (racCounter == 0) {
                    failedRacFound = true;
                }
            }
        }
        assertTrue(validRacFound);
        assertTrue(failedRacFound);
        assertTrue(racWithAllFailedIssuerRacsFound);
        assertTrue(racWithOneFailedIssuerRacFound);
    }

    @Test
    void unknownRevocationTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_unknown_revocation.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCUKN_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(sigBBB);

        XmlXCV xcv = sigBBB.getXCV();
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV subXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

        boolean acceptableRevocationCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getError().getKey());
                acceptableRevocationCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(acceptableRevocationCheckFound);

        XmlCRS crs = subXCV.getCRS();
        assertEquals(Indication.INDETERMINATE, crs.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, crs.getConclusion().getSubIndication());

        List<XmlRAC> racs = crs.getRAC();
        assertEquals(1, racs.size());

        XmlRAC xmlRAC = racs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlRAC.getConclusion().getSubIndication());

        boolean revocationStatusKnownCheckFound = false;
        for (XmlConstraint constraint : xmlRAC.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCUKN.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCUKN_ANS.getId(), constraint.getError().getKey());
                revocationStatusKnownCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(revocationStatusKnownCheckFound);
    }

}
