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
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS2338ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void expiredOCSPResponderTest() throws Exception {
        // see DSS-2338
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_expired_ocsp_responder.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
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
        CertificateRevocationWrapper revocationWrapper = certificateRevocationData.get(0);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
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
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        boolean acceptableRevocationCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getError().getKey());
                acceptableRevocationCheckFound = true;
            }
        }
        assertTrue(acceptableRevocationCheckFound);

        List<XmlRAC> rac = subXCV.getCRS().getRAC();
        assertEquals(1, rac.size());

        XmlRAC xmlRAC = rac.get(0);
        assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlRAC.getConclusion().getSubIndication());

        boolean consistencyCheckFound = false;
        for (XmlConstraint constraint : xmlRAC.getConstraint()) {
            if (MessageTag.BBB_XCV_REVOC_ISSUER_VALID_AT_PROD.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_REVOC_ISSUER_VALID_AT_PROD_ANS.getId(), constraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_PRODUCED_AT_OUT_OF_BOUNDS,
                                ValidationProcessUtils.getFormattedDate(revocationWrapper.getProductionDate()),
                                ValidationProcessUtils.getFormattedDate(revocationWrapper.getSigningCertificate().getNotBefore()),
                                ValidationProcessUtils.getFormattedDate(revocationWrapper.getSigningCertificate().getNotAfter())),
                        constraint.getAdditionalInfo());
                consistencyCheckFound = true;
            }
        }
        assertTrue(consistencyCheckFound);
    }

    @Test
    void expiredOCSPResponderWithInformLevelTest() throws Exception {
        // see DSS-2338
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_expired_ocsp_responder.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();
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
        CertificateRevocationWrapper revocationWrapper = certificateRevocationData.get(0);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        XmlSubXCV subXCV = subXCVs.get(0);
        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        boolean acceptableRevocationCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getInfo().getKey());
                acceptableRevocationCheckFound = true;
            }
        }
        assertTrue(acceptableRevocationCheckFound);

        List<XmlRAC> rac = subXCV.getCRS().getRAC();
        assertEquals(1, rac.size());

        XmlRAC xmlRAC = rac.get(0);
        assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlRAC.getConclusion().getSubIndication());

        boolean consistencyCheckFound = false;
        for (XmlConstraint constraint : xmlRAC.getConstraint()) {
            if (MessageTag.BBB_XCV_REVOC_ISSUER_VALID_AT_PROD.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_REVOC_ISSUER_VALID_AT_PROD_ANS.getId(), constraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_PRODUCED_AT_OUT_OF_BOUNDS,
                                ValidationProcessUtils.getFormattedDate(revocationWrapper.getProductionDate()),
                                ValidationProcessUtils.getFormattedDate(revocationWrapper.getSigningCertificate().getNotBefore()),
                                ValidationProcessUtils.getFormattedDate(revocationWrapper.getSigningCertificate().getNotAfter())),
                        constraint.getAdditionalInfo());
                consistencyCheckFound = true;
            }
        }
        assertTrue(consistencyCheckFound);
    }

    @Test
    void skipRevocationCheckTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_expired_ocsp_responder.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();
        CertificateConstraints signingCertificateConstraints = basicSignatureConstraints.getSigningCertificate();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.INFORM);
        signingCertificateConstraints.setAcceptableRevocationDataFound(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
        executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        XmlSubXCV subXCV = subXCVs.get(0);
        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getInfos()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));
    }

}
