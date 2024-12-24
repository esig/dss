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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OCSPResponderValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void ocspWithWrongResponderIdTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_wrong_responderid.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getRevocationConstraints().setOCSPResponderIdMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_RESPID_MATCH_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, sigBBB.getConclusion().getSubIndication());

        XmlXCV xcv = sigBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

        boolean acceptableRevocDataCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getError().getKey());
                acceptableRevocDataCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(acceptableRevocDataCheckFound);

        XmlCRS crs = subXCV.getCRS();
        assertNotNull(crs);
        assertEquals(Indication.INDETERMINATE, crs.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, crs.getConclusion().getSubIndication());

        boolean revocAcceptanceCheckFound = false;
        acceptableRevocDataCheckFound = false;
        for (XmlConstraint constraint : crs.getConstraint()) {
            if (MessageTag.BBB_XCV_RAC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_RAC_ANS.getId(), constraint.getWarning().getKey());
                revocAcceptanceCheckFound = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getError().getKey());
                acceptableRevocDataCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(revocAcceptanceCheckFound);
        assertTrue(acceptableRevocDataCheckFound);

        List<XmlRAC> racs = crs.getRAC();
        assertEquals(1, racs.size());

        XmlRAC xmlRAC = racs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlRAC.getConclusion().getSubIndication());

        boolean responderIdCheckFound = false;
        for (XmlConstraint constraint : xmlRAC.getConstraint()) {
            if (MessageTag.BBB_XCV_REVOC_RESPID_MATCH.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_REVOC_RESPID_MATCH_ANS.getId(), constraint.getError().getKey());
                responderIdCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(responderIdCheckFound);
    }

    @Test
    void ocspWithWrongResponderIdWarnTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_wrong_responderid.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getRevocationConstraints().setOCSPResponderIdMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_RESPID_MATCH_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlXCV xcv = sigBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

        XmlCRS crs = subXCV.getCRS();
        assertNotNull(crs);
        assertEquals(Indication.PASSED, crs.getConclusion().getIndication());

        List<XmlRAC> racs = crs.getRAC();
        assertEquals(1, racs.size());

        XmlRAC xmlRAC = racs.get(0);
        assertEquals(Indication.PASSED, xmlRAC.getConclusion().getIndication());

        boolean responderIdCheckFound = false;
        for (XmlConstraint constraint : xmlRAC.getConstraint()) {
            if (MessageTag.BBB_XCV_REVOC_RESPID_MATCH.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_REVOC_RESPID_MATCH_ANS.getId(), constraint.getWarning().getKey());
                responderIdCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(responderIdCheckFound);
    }
}
