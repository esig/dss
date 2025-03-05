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
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS2805ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void ocspExpiredLTTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2805/dss-2805-ocsp-expired.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRCIRI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRCIRI_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV xmlSubXCV = xcv.getSubXCV().get(0);

        boolean revocationCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRCIRI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRCIRI_ANS.getId(), constraint.getError().getKey());
                revocationCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(revocationCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);
        assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, validationProcessLongTermData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessLongTermData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRCIRI_ANS)));

        boolean bsvAcceptableCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ABSV.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.LTV_ABSV_ANS.getId(), constraint.getError().getKey());
                bsvAcceptableCheckFound = true;
            }
        }
        assertTrue(bsvAcceptableCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, validationProcessArchivalData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRCIRI_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));

        boolean ltaDataPresentCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), constraint.getError().getKey());
                ltaDataPresentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(ltaDataPresentCheckFound);
    }

    @Test
    void ocspExpiredLTATest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2805/dss-2805-ocsp-expired-lta.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRCIRI_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV xmlSubXCV = xcv.getSubXCV().get(0);

        boolean revocationCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRCIRI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRCIRI_ANS.getId(), constraint.getError().getKey());
                revocationCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(revocationCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);
        assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, validationProcessLongTermData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessLongTermData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRCIRI_ANS)));

        boolean bsvAcceptableCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ABSV.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.LTV_ABSV_ANS.getId(), constraint.getError().getKey());
                bsvAcceptableCheckFound = true;
            }
        }
        assertTrue(bsvAcceptableCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean ltaDataPresentCheckFound = false;
        boolean psvCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ltaDataPresentCheckFound = true;
            } else if (MessageTag.PSV_IPSVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                psvCheckFound = true;
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                // ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(ltaDataPresentCheckFound);
        assertTrue(psvCheckFound);
    }

    @Test
    void ocspExpiredOnlineGoodOcspTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2805/dss-2805-ocsp-expired-online.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.PASSED, validationProcessBasicSignature.getConclusion().getIndication());

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV xmlSubXCV = xcv.getSubXCV().get(0);

        boolean revocationCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_XCV_ICTIVRCIRI.getId().equals(constraint.getName().getKey())) {
                revocationCheckFound = true;
            }
        }
        assertTrue(revocationCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);
        assertEquals(Indication.PASSED, validationProcessLongTermData.getConclusion().getIndication());

        boolean bsvAcceptableCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ABSV.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                bsvAcceptableCheckFound = true;
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                // ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(bsvAcceptableCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean ltaDataPresentCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), constraint.getInfo().getKey());
                ltaDataPresentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(ltaDataPresentCheckFound);
    }

    @Test
    void ocspAndSignCertExpiredTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2805/dss-2805.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV xmlSubXCV = xcv.getSubXCV().get(0);

        boolean certValidityRangeCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), constraint.getError().getKey());
                certValidityRangeCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(certValidityRangeCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean bstNotBeforeCertIssuanceCheckFound = false;
        boolean certKnownToBeNotRevokedCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.TSV_IBSTAIDOSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                bstNotBeforeCertIssuanceCheckFound = true;
            } else if (MessageTag.LTV_ISCKNR.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), constraint.getError().getKey());
                certKnownToBeNotRevokedCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(bstNotBeforeCertIssuanceCheckFound);
        assertTrue(certKnownToBeNotRevokedCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean ltaDataPresentCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), constraint.getError().getKey());
                ltaDataPresentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(ltaDataPresentCheckFound);
    }

    @Test
    void ocspAndSignCertExpiredWithFreshGoodRevocationTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2805/dss-2805-online.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV xmlSubXCV = xcv.getSubXCV().get(0);

        boolean certValidityRangeCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), constraint.getError().getKey());
                certValidityRangeCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(certValidityRangeCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean bstNotBeforeCertIssuanceCheckFound = false;
        boolean certKnownToBeNotRevokedCheckFound = false;
        boolean bstNotAfterCertValidityCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.TSV_IBSTAIDOSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                bstNotBeforeCertIssuanceCheckFound = true;
            } else if (MessageTag.LTV_ISCKNR.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                certKnownToBeNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                bstNotAfterCertValidityCheckFound = true;
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                //ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(bstNotBeforeCertIssuanceCheckFound);
        assertTrue(certKnownToBeNotRevokedCheckFound);
        assertTrue(bstNotAfterCertValidityCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean ltaDataPresentCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                ltaDataPresentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(ltaDataPresentCheckFound);
    }

    @Test
    void ocspAndSignCertExpiredWithFreshUnknownRevocationTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2805/dss-2805-online-unknown.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV xmlSubXCV = xcv.getSubXCV().get(0);

        boolean certValidityRangeCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), constraint.getError().getKey());
                certValidityRangeCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(certValidityRangeCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean bstNotBeforeCertIssuanceCheckFound = false;
        boolean certKnownToBeNotRevokedCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.TSV_IBSTAIDOSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                bstNotBeforeCertIssuanceCheckFound = true;
            } else if (MessageTag.LTV_ISCKNR.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), constraint.getError().getKey());
                certKnownToBeNotRevokedCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(bstNotBeforeCertIssuanceCheckFound);
        assertTrue(certKnownToBeNotRevokedCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean ltaDataPresentCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), constraint.getError().getKey());
                ltaDataPresentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(ltaDataPresentCheckFound);
    }

    @Test
    void ocspAndSignCertExpiredLTATest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2805/dss-2805-lta.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV xmlSubXCV = xcv.getSubXCV().get(0);

        boolean certValidityRangeCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICTIVRSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICTIVRSC_ANS.getId(), constraint.getError().getKey());
                certValidityRangeCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(certValidityRangeCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean bstNotBeforeCertIssuanceCheckFound = false;
        boolean certKnownToBeNotRevokedCheckFound = false;
        boolean bstNotAfterCertValidityCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.TSV_IBSTAIDOSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                bstNotBeforeCertIssuanceCheckFound = true;
            } else if (MessageTag.LTV_ISCKNR.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.LTV_ISCKNR_ANS1.getId(), constraint.getError().getKey());
                certKnownToBeNotRevokedCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(constraint.getName().getKey())) {
                bstNotAfterCertValidityCheckFound = true;
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                //ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(bstNotBeforeCertIssuanceCheckFound);
        assertTrue(certKnownToBeNotRevokedCheckFound);
        assertFalse(bstNotAfterCertValidityCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertNotNull(validationProcessArchivalData);

        boolean ltaDataPresentCheckFound = false;
        boolean psvCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ARCH_LTAIVMP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ltaDataPresentCheckFound = true;
            } else if (MessageTag.PSV_IPSVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                psvCheckFound = true;
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                //ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(ltaDataPresentCheckFound);
        assertTrue(psvCheckFound);
    }

}
