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
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS2913ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void asicValidIndependentTstTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_tst_asic.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
        levelConstraint.setLevel(Level.FAIL);
        levelConstraint.getId().add(ASiCContainerType.ASiC_E.toString());
        validationPolicy.getContainerConstraints().setAcceptableContainerTypes(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstTimestampId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IECTF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(simpleReport.getFirstTimestampId()));

        XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstTimestampId());
        assertNotNull(tstBBB);
        assertEquals(Indication.PASSED, tstBBB.getConclusion().getIndication());

        XmlFC fc = tstBBB.getFC();
        assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

        boolean containerCheckFound = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            if (MessageTag.BBB_FC_IECTF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                containerCheckFound = true;
            }
        }
        assertTrue(containerCheckFound);
    }

    @Test
    void asicInvalidIndependentTstTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_tst_asic.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
        levelConstraint.setLevel(Level.FAIL);
        levelConstraint.getId().add(ASiCContainerType.ASiC_S.toString());
        validationPolicy.getContainerConstraints().setAcceptableContainerTypes(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstTimestampId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstTimestampId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IECTF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getBasicTimestampValidationIndication(simpleReport.getFirstTimestampId()));
        assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(simpleReport.getFirstTimestampId()));

        XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstTimestampId());
        assertNotNull(tstBBB);
        assertEquals(Indication.FAILED, tstBBB.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, tstBBB.getConclusion().getSubIndication());

        XmlFC fc = tstBBB.getFC();
        assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

        boolean containerCheckFound = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            if (MessageTag.BBB_FC_IECTF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_IECTF_ANS.getId(), constraint.getError().getKey());
                containerCheckFound = true;
            }
        }
        assertTrue(containerCheckFound);
    }

}
