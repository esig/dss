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
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateOnHoldValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void certificateOnHoldWithTimestampBeforeSuspensionTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_on_hold_with_tst_before.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlXCV xcv = signatureBBB.getXCV();
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV subXCV = subXCVs.get(0);
        boolean onHoldCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCOH.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCOH_ANS.getId(), constraint.getError().getKey());
                onHoldCheckFound = true;
            }
        }
        assertTrue(onHoldCheckFound);

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertEquals(Indication.PASSED, validationProcessLongTermData.getConclusion().getIndication());

        onHoldCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.ADEST_ISTPTBST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                onHoldCheckFound = true;
            }
        }
        assertTrue(onHoldCheckFound);
    }

    @Test
    void certificateOnHoldWithTimestampAfterSuspensionTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_cert_on_hold_with_tst_after.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> validationErrors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(Utils.isCollectionNotEmpty(validationErrors));
        assertTrue(checkMessageValuePresence(validationErrors, i18nProvider.getMessage(MessageTag.BBB_XCV_ISCOH_ANS)));
        assertTrue(checkMessageValuePresence(validationErrors, i18nProvider.getMessage(MessageTag.ADEST_ISTPTBST_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlXCV xcv = signatureBBB.getXCV();
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV subXCV = subXCVs.get(0);
        boolean onHoldCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCOH.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCOH_ANS.getId(), constraint.getError().getKey());
                onHoldCheckFound = true;
            }
        }
        assertTrue(onHoldCheckFound);

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessLongTermData.getConclusion().getSubIndication());

        onHoldCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.ADEST_ISTPTBST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ADEST_ISTPTBST_ANS.getId(), constraint.getError().getKey());
                onHoldCheckFound = true;
            }
        }
        assertTrue(onHoldCheckFound);
    }

}
