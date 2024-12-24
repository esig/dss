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
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFAInfo;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PDFAValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void pdfaValidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pdfa.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint valuesConstraint = new MultiValuesConstraint();
        valuesConstraint.setLevel(Level.FAIL);
        valuesConstraint.getId().add("PDF/A-2A");
        valuesConstraint.getId().add("PDF/A-2B");
        valuesConstraint.getId().add("PDF/A-2U");
        validationPolicy.getPDFAConstraints().setAcceptablePDFAProfiles(valuesConstraint);

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlFC fc = signatureBBB.getFC();
        assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

        boolean pdfAFormatCheckFound = false;
        boolean pdfAComplianceCheckFound = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            if (MessageTag.BBB_FC_DDAPDFAF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pdfAFormatCheckFound = true;
            } else if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pdfAComplianceCheckFound = true;
            }
        }
        assertTrue(pdfAFormatCheckFound);
        assertTrue(pdfAComplianceCheckFound);
    }

    @Test
    void pdfaWrongFormatTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pdfa.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint valuesConstraint = new MultiValuesConstraint();
        valuesConstraint.setLevel(Level.FAIL);
        valuesConstraint.getId().add("PDF/A-2B");
        valuesConstraint.getId().add("PDF/A-2U");
        validationPolicy.getPDFAConstraints().setAcceptablePDFAProfiles(valuesConstraint);

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_DDAPDFAF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());

        XmlFC fc = signatureBBB.getFC();
        assertEquals(Indication.FAILED, fc.getConclusion().getIndication());

        boolean pdfAFormatCheckFound = false;
        boolean pdfAComplianceCheckFound = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            if (MessageTag.BBB_FC_DDAPDFAF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_DDAPDFAF_ANS.getId(), constraint.getError().getKey());
                pdfAFormatCheckFound = true;
            } else if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pdfAComplianceCheckFound = true;
            }
        }
        assertTrue(pdfAFormatCheckFound);
        assertFalse(pdfAComplianceCheckFound);
    }

    @Test
    void pdfaInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pdfa.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getPDFAInfo().setCompliant(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint valuesConstraint = new MultiValuesConstraint();
        valuesConstraint.setLevel(Level.FAIL);
        valuesConstraint.getId().add("PDF/A-2A");
        valuesConstraint.getId().add("PDF/A-2B");
        valuesConstraint.getId().add("PDF/A-2U");
        validationPolicy.getPDFAConstraints().setAcceptablePDFAProfiles(valuesConstraint);

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IDPDFAC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());

        XmlFC fc = signatureBBB.getFC();
        assertEquals(Indication.FAILED, fc.getConclusion().getIndication());

        boolean pdfAFormatCheckFound = false;
        boolean pdfAComplianceCheckFound = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            if (MessageTag.BBB_FC_DDAPDFAF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pdfAFormatCheckFound = true;
            } else if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_IDPDFAC_ANS.getId(), constraint.getError().getKey());
                pdfAComplianceCheckFound = true;
            }
        }
        assertTrue(pdfAFormatCheckFound);
        assertTrue(pdfAComplianceCheckFound);
    }

    @Test
    void pdfaValidIndependentTstTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_tst_pdfa_invalid.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getPDFAInfo().setCompliant(true);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstTimestampId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(simpleReport.getFirstTimestampId()));

        XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstTimestampId());
        assertNotNull(tstBBB);
        assertEquals(Indication.PASSED, tstBBB.getConclusion().getIndication());

        XmlFC fc = tstBBB.getFC();
        assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

        boolean pdfAComplianceCheckFound = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
                pdfAComplianceCheckFound = true;
            }
        }
        assertTrue(pdfAComplianceCheckFound);
    }

    @Test
    void pdfaInvalidIndependentTstTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_tst_pdfa_invalid.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getPDFAInfo().setCompliant(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

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
                i18nProvider.getMessage(MessageTag.BBB_FC_IDPDFAC_ANS)));

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

        boolean pdfAComplianceCheckFound = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_IDPDFAC_ANS.getId(), constraint.getError().getKey());
                pdfAComplianceCheckFound = true;
            }
        }
        assertTrue(pdfAComplianceCheckFound);
    }

    @Test
    void pdfaInvalidEnclosedTstWithUndefinedChangesWarnTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pades_lta_mod_tst.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlPDFAInfo xmlPDFAInfo = new XmlPDFAInfo();
        xmlPDFAInfo.setCompliant(false);
        xmlDiagnosticData.setPDFAInfo(xmlPDFAInfo);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

        levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().setUndefinedChanges(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        DetailedReport detailedReport = reports.getDetailedReport();

        boolean sigTstFound = false;
        boolean arcTstFound = false;
        List<XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : signatureTimestamps) {
            assertEquals(Indication.PASSED, simpleReport.getIndication(timestamp.getId()));

            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
            assertNotNull(tstBBB);
            assertEquals(Indication.PASSED, tstBBB.getConclusion().getIndication());

            if (tstBBB.getFC() == null) {
                assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(timestamp.getId())));
                assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(timestamp.getId())));
                sigTstFound = true;

            } else {
                assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(timestamp.getId())));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(timestamp.getId()),
                        i18nProvider.getMessage(MessageTag.BBB_FC_DSCNUOM_ANS)));

                XmlFC fc = tstBBB.getFC();
                assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

                boolean pdfAComplianceCheckFound = false;
                boolean undefinedChangesFound = false;
                for (XmlConstraint constraint : fc.getConstraint()) {
                    if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
                        pdfAComplianceCheckFound = true;

                    } else if (MessageTag.BBB_FC_DSCNUOM.getId().equals(constraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, constraint.getStatus());
                        assertEquals(MessageTag.BBB_FC_DSCNUOM_ANS.getId(), constraint.getWarning().getKey());
                        undefinedChangesFound = true;

                    } else {
                        assertEquals(XmlStatus.OK, constraint.getStatus());
                    }
                }
                assertFalse(pdfAComplianceCheckFound);
                assertTrue(undefinedChangesFound);
                arcTstFound = true;
            }
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);
    }

}
