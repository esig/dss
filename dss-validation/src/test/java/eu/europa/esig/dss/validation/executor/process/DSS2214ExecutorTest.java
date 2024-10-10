/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
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
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS2214ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void dss2214NoRevocationDataTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_no_revocation_data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setRevocationDataAvailable(levelConstraint);
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setAcceptableRevocationDataFound(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(3, xcv.getSubXCV().size());

        boolean revocationDataPresentCheck = false;
        boolean acceptableRevocationDataCheck = false;
        XmlSubXCV subXCV = xcv.getSubXCV().iterator().next();
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IRDPFC_ANS.getId(), constraint.getWarning().getKey());
                revocationDataPresentCheck = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
                acceptableRevocationDataCheck = true;
            }
        }
        assertTrue(revocationDataPresentCheck);
        assertFalse(acceptableRevocationDataCheck);

        assertEquals(1, detailedReport.getSignatures().size());
        XmlValidationProcessLongTermData ltvProcess = detailedReport.getSignatures().iterator().next().getValidationProcessLongTermData();
        assertNotNull(ltvProcess);

        revocationDataPresentCheck = false;
        acceptableRevocationDataCheck = false;
        for (XmlConstraint constraint : ltvProcess.getConstraint()) {
            if (subXCV.getId().equals(constraint.getId())) {
                if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.BBB_XCV_IRDPFC_ANS.getId(), constraint.getWarning().getKey());
                    revocationDataPresentCheck = true;
                } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
                    acceptableRevocationDataCheck = true;
                }
            }
        }
        assertTrue(revocationDataPresentCheck);
        assertFalse(acceptableRevocationDataCheck);

        checkReports(reports);
    }

    @Test
    void dss2214NoRevocationDataAvailableCheckSkippedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_no_revocation_data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setRevocationDataAvailable(null);
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setAcceptableRevocationDataFound(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(3, xcv.getSubXCV().size());

        boolean revocationDataPresentCheck = false;
        boolean acceptableRevocationDataCheck = false;
        XmlSubXCV subXCV = xcv.getSubXCV().iterator().next();
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IRDPFC_ANS.getId(), constraint.getWarning().getKey());
                revocationDataPresentCheck = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
                acceptableRevocationDataCheck = true;
            }
        }
        assertFalse(revocationDataPresentCheck);
        assertFalse(acceptableRevocationDataCheck);

        assertEquals(1, detailedReport.getSignatures().size());
        XmlValidationProcessLongTermData ltvProcess = detailedReport.getSignatures().iterator().next().getValidationProcessLongTermData();
        assertNotNull(ltvProcess);

        revocationDataPresentCheck = false;
        acceptableRevocationDataCheck = false;
        for (XmlConstraint constraint : ltvProcess.getConstraint()) {
            if (subXCV.getId().equals(constraint.getId())) {
                if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.BBB_XCV_IRDPFC_ANS.getId(), constraint.getWarning().getKey());
                    revocationDataPresentCheck = true;
                } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
                    acceptableRevocationDataCheck = true;
                }
            }
        }
        assertFalse(revocationDataPresentCheck);
        assertFalse(acceptableRevocationDataCheck);

        checkReports(reports);
    }

    @Test
    void dss2214BadRevocationDataTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_bad_revocation_data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setRevocationDataAvailable(levelConstraint);
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setAcceptableRevocationDataFound(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(3, xcv.getSubXCV().size());

        boolean revocationDataPresentCheck = false;
        boolean acceptableRevocationDataCheck = false;
        XmlSubXCV subXCV = xcv.getSubXCV().iterator().next();
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                revocationDataPresentCheck = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
                acceptableRevocationDataCheck = true;
            }
        }
        assertTrue(revocationDataPresentCheck);
        assertTrue(acceptableRevocationDataCheck);

        assertEquals(1, detailedReport.getSignatures().size());
        XmlValidationProcessLongTermData ltvProcess = detailedReport.getSignatures().iterator().next().getValidationProcessLongTermData();
        assertNotNull(ltvProcess);

        revocationDataPresentCheck = false;
        acceptableRevocationDataCheck = false;
        for (XmlConstraint constraint : ltvProcess.getConstraint()) {
            if (subXCV.getId().equals(constraint.getId())) {
                if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    revocationDataPresentCheck = true;
                } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
                    acceptableRevocationDataCheck = true;
                }
            }
        }
        assertTrue(revocationDataPresentCheck);
        assertTrue(acceptableRevocationDataCheck);

        checkReports(reports);
    }

    @Test
    void dss2214BadRevocationDataNoPresenceCheckTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_bad_revocation_data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setRevocationDataAvailable(null);
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setAcceptableRevocationDataFound(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(3, xcv.getSubXCV().size());

        boolean revocationDataPresentCheck = false;
        boolean acceptableRevocationDataCheck = false;
        XmlSubXCV subXCV = xcv.getSubXCV().iterator().next();
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                revocationDataPresentCheck = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
                acceptableRevocationDataCheck = true;
            }
        }
        assertFalse(revocationDataPresentCheck);
        assertTrue(acceptableRevocationDataCheck);

        assertEquals(1, detailedReport.getSignatures().size());
        XmlValidationProcessLongTermData ltvProcess = detailedReport.getSignatures().iterator().next().getValidationProcessLongTermData();
        assertNotNull(ltvProcess);

        revocationDataPresentCheck = false;
        acceptableRevocationDataCheck = false;
        for (XmlConstraint constraint : ltvProcess.getConstraint()) {
            if (subXCV.getId().equals(constraint.getId())) {
                if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    revocationDataPresentCheck = true;
                } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
                    acceptableRevocationDataCheck = true;
                }
            }
        }
        assertFalse(revocationDataPresentCheck);
        assertTrue(acceptableRevocationDataCheck);

        checkReports(reports);
    }

}
