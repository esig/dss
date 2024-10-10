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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.ContainerConstraints;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASICValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void testAllFilesCovered() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/all-files-present.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        List<Message> warnings = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId());
        assertFalse(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.BBB_CV_IAFS_ANS)));
        assertTrue(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.BBB_ICS_AIDNASNE_ANS)));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testNotAllFilesCovered() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/all-files-present.xml"));
        assertNotNull(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        containerInfo.getContentFiles().add("bye.world");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        containerConstraints.setAllFilesSigned(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertNotNull(validationProcessBasicSignature.getTitle());
        assertNotNull(validationProcessBasicSignature.getProofOfExistence());

        boolean fcCheckFound = false;
        for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
            if (MessageTag.BSV_IFCRC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                fcCheckFound = true;
            }
        }
        assertTrue(fcCheckFound);

        assertFalse(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BSV_IFCRC_ANS)));

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertEquals(validationProcessBasicSignature.getConclusion().getErrors(), validationProcessLongTermData.getConclusion().getErrors());
        assertEquals(validationProcessBasicSignature.getConclusion().getWarnings(), validationProcessLongTermData.getConclusion().getWarnings());
        assertEquals(validationProcessBasicSignature.getConclusion().getInfos(), validationProcessLongTermData.getConclusion().getInfos());

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(validationProcessBasicSignature.getConclusion().getErrors(), validationProcessArchivalData.getConclusion().getErrors());
        assertEquals(validationProcessBasicSignature.getConclusion().getWarnings(), validationProcessArchivalData.getConclusion().getWarnings());
        assertEquals(validationProcessBasicSignature.getConclusion().getInfos(), validationProcessArchivalData.getConclusion().getInfos());

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_CV_IAFS_ANS)));
        assertFalse(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.LTV_ABSV_ANS)));
        assertFalse(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.ARCH_LTVV_ANS)));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void multiFiles() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/asic-e-multi-files-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void multiFilesNoManifest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/asic-e-multi-files-no-manifest-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IMFP_ASICE_ANS)));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void asicEXades() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/asic-e-xades-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void openDocumentCoverageTest() throws Exception {
        // see DSS-2448
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_open_document.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.setLevel(Level.FAIL);
        multiValuesConstraint.getId().add("application/vnd.oasis.opendocument.text");
        containerConstraints.setAcceptableMimeTypeFileContent(multiValuesConstraint);

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        containerConstraints.setAllFilesSigned(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void asicNoMimetypeSkipCheckTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/asic-s-xades-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        containerInfo.setMimeTypeFilePresent(false);
        containerInfo.setMimeTypeContent(null);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(null);
        containerConstraints.setMimeTypeFilePresent(levelConstraint);

        MultiValuesConstraint acceptableMimetype = new MultiValuesConstraint();
        acceptableMimetype.getId().add("application/vnd.etsi.asic-s+zip");
        acceptableMimetype.getId().add("application/vnd.etsi.asic-e+zip");
        acceptableMimetype.setLevel(Level.FAIL);
        containerConstraints.setAcceptableMimeTypeFileContent(acceptableMimetype);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void asicNoMimetypeFailLevelTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/asic-s-xades-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        containerInfo.setMimeTypeFilePresent(false);
        containerInfo.setMimeTypeContent(null);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        containerConstraints.setMimeTypeFilePresent(levelConstraint);

        MultiValuesConstraint acceptableMimetype = new MultiValuesConstraint();
        acceptableMimetype.getId().add("application/vnd.etsi.asic-s+zip");
        acceptableMimetype.getId().add("application/vnd.etsi.asic-e+zip");
        acceptableMimetype.setLevel(Level.FAIL);
        containerConstraints.setAcceptableMimeTypeFileContent(acceptableMimetype);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_ITMFP_ANS)));

        checkReports(reports);
    }

    @Test
    void asicNotAcceptableMimeTypeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/asic-s-xades-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        containerInfo.setMimeTypeFilePresent(true);
        containerInfo.setMimeTypeContent("test-content");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        containerConstraints.setMimeTypeFilePresent(levelConstraint);

        MultiValuesConstraint acceptableMimetype = new MultiValuesConstraint();
        acceptableMimetype.getId().add("application/vnd.etsi.asic-s+zip");
        acceptableMimetype.getId().add("application/vnd.etsi.asic-e+zip");
        acceptableMimetype.setLevel(Level.FAIL);
        containerConstraints.setAcceptableMimeTypeFileContent(acceptableMimetype);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IEMCF_ANS)));

        checkReports(reports);
    }

    @Test
    void asicZipCommentSkipCheckTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/asic-s-xades-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        containerInfo.setZipComment(null);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(null);
        containerConstraints.setZipCommentPresent(levelConstraint);

        MultiValuesConstraint acceptableZipComment = new MultiValuesConstraint();
        acceptableZipComment.getId().add("application/vnd.etsi.asic-s+zip");
        acceptableZipComment.getId().add("application/vnd.etsi.asic-e+zip");
        acceptableZipComment.setLevel(Level.FAIL);
        containerConstraints.setAcceptableZipComment(acceptableZipComment);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void asicZipCommentFailLevelTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/asic-s-xades-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        containerInfo.setZipComment(null);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        containerConstraints.setZipCommentPresent(levelConstraint);

        MultiValuesConstraint acceptableZipComment = new MultiValuesConstraint();
        acceptableZipComment.getId().add("application/vnd.etsi.asic-s+zip");
        acceptableZipComment.getId().add("application/vnd.etsi.asic-e+zip");
        acceptableZipComment.setLevel(Level.FAIL);
        containerConstraints.setAcceptableZipComment(acceptableZipComment);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_ITZCP_ANS)));

        checkReports(reports);
    }

    @Test
    void asicNotAcceptableZipCommentTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/asic-s-xades-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        containerInfo.setZipComment("test-comment");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        containerConstraints.setZipCommentPresent(levelConstraint);

        MultiValuesConstraint acceptableZipComment = new MultiValuesConstraint();
        acceptableZipComment.getId().add("application/vnd.etsi.asic-s+zip");
        acceptableZipComment.getId().add("application/vnd.etsi.asic-e+zip");
        acceptableZipComment.setLevel(Level.FAIL);
        containerConstraints.setAcceptableZipComment(acceptableZipComment);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_ITEZCF_ANS)));

        checkReports(reports);
    }

}
