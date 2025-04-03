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
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIdPkixOcspNoCheck;
import eu.europa.esig.dss.diagnostic.jaxb.XmlKeyUsages;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectAlternativeNames;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RFC5280ValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void noRevocationAccessPointsTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/no-revoc-access-points.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        EtsiValidationPolicy defaultPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setRevocationInfoAccessPresent(levelConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_PRES_ANS)));
    }

    @Test
    void noAIATest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSigningCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate();
        CertificateWrapper certificateWrapper = new CertificateWrapper(signingCertificate.getCertificate());
        certificateWrapper.getCAIssuersAccessUrls().clear();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        EtsiValidationPolicy defaultPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setAuthorityInfoAccessPresent(levelConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_AIA_PRES_ANS)));
    }

    @Test
    void certificatePolicyIdsTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy oid = new XmlCertificatePolicy();
        oid.setValue("1.3.76.38.1.1.2");
        xmlCertificatePolicies.getCertificatePolicy().add(oid);
        signingCertificate.getCertificateExtensions().add(xmlCertificatePolicies);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("1.3.76.38.1.1.1");
        certificateConstraints.setPolicyIds(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIPI_ANS)));

        // should be able to process
        oid.setValue(null);

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIPI_ANS)));

        oid.setValue("");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIPI_ANS)));

        oid.setValue(" ");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIPI_ANS)));

        oid.setValue("1.3.76.38.1.1.1");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void certificatePolicyQualifiedIdsTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();

        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy oid = new XmlCertificatePolicy();
        oid.setValue(CertificatePolicy.NCPP.getOid());
        xmlCertificatePolicies.getCertificatePolicy().add(oid);
        signingCertificate.getCertificateExtensions().add(xmlCertificatePolicies);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        certificateConstraints.setPolicyQualificationIds(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIQC_ANS)));

        oid.setValue(CertificatePolicy.QCP_PUBLIC.getOid());

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void certificatePolicySupportedByQSCDIdsTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
        xmlCertificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
        XmlCertificatePolicy oid = new XmlCertificatePolicy();
        oid.setValue(CertificatePolicy.NCPP.getOid());
        xmlCertificatePolicies.getCertificatePolicy().add(oid);
        signingCertificate.getCertificateExtensions().add(xmlCertificatePolicies);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        certificateConstraints.setPolicySupportedByQSCDIds(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIQSCD_ANS)));

        oid.setValue(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid());

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void signCertKeyUsageValidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(KeyUsageBit.NON_REPUDIATION.getValue());
        multiValuesConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setKeyUsage(multiValuesConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

        assertEquals(3, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

        boolean keyCertCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_XCV_ISCGKU.getId().equals(constraint.getName().getKey())) {
                keyCertCheckFound = true;
            }
        }
        assertTrue(keyCertCheckFound);
    }

    @Test
    void signCertKeyUsageInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(KeyUsageBit.DIGITAL_SIGNATURE.getValue());
        multiValuesConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setKeyUsage(multiValuesConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGKU_ANS, MessageTag.SIGNING_CERTIFICATE, MessageTag.SIGNATURE)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, xcv.getConclusion().getSubIndication());

        assertEquals(3, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, subXCV.getConclusion().getSubIndication());

        boolean keyCertCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCGKU.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCGKU_ANS.getId(), constraint.getError().getKey());
                keyCertCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(keyCertCheckFound);
    }

    @Test
    void caCertKeyUsageInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlSigningCertificate caCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate()
                .getCertificate().getSigningCertificate();
        CertificateWrapper certificateWrapper = new CertificateWrapper(caCertificate.getCertificate());
        certificateWrapper.getKeyUsages().clear();

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(KeyUsageBit.KEY_CERT_SIGN.getValue());
        multiValuesConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getCACertificate().setKeyUsage(multiValuesConstraint);

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
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGKU_ANS, MessageTag.CA_CERTIFICATE, MessageTag.SIGNATURE)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

        assertEquals(3, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(1);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

        boolean keyCertCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCGKU.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCGKU_ANS.getId(), constraint.getError().getKey());
                keyCertCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(keyCertCheckFound);
    }

    @Test
    void signCertExtendedKeyUsageValidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        String timestampId = xmlDiagnosticData.getUsedTimestamps().get(0).getId();

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(ExtendedKeyUsage.TIMESTAMPING.getDescription());
        multiValuesConstraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setExtendedKeyUsage(multiValuesConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.PASSED, simpleReport.getIndication(timestampId));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(timestampId)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestampId));

        XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestampId);
        assertNotNull(tstBBB);
        assertEquals(Indication.PASSED, tstBBB.getConclusion().getIndication());

        XmlXCV xcv = tstBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

        boolean extendedKeyCertCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_XCV_ISCGEKU.getId().equals(constraint.getName().getKey())) {
                extendedKeyCertCheckFound = true;
            }
        }
        assertTrue(extendedKeyCertCheckFound);
    }

    @Test
    void signCertExtendedKeyUsageInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
        CertificateWrapper certificateWrapper = new CertificateWrapper(xmlTimestamp.getSigningCertificate().getCertificate());
        certificateWrapper.getExtendedKeyUsages().clear();

        String timestampId = xmlTimestamp.getId();

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(ExtendedKeyUsage.TIMESTAMPING.getDescription());
        multiValuesConstraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setExtendedKeyUsage(multiValuesConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(timestampId));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(timestampId));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(timestampId),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGEKU_ANS, MessageTag.SIGNING_CERTIFICATE, MessageTag.TIMESTAMP)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(timestampId));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(timestampId));

        XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestampId);
        assertNotNull(tstBBB);
        assertEquals(Indication.INDETERMINATE, tstBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, tstBBB.getConclusion().getSubIndication());

        XmlXCV xcv = tstBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, xcv.getConclusion().getSubIndication());

        assertEquals(2, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, subXCV.getConclusion().getSubIndication());

        boolean extendedKeyCertCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCGEKU.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCGEKU_ANS.getId(), constraint.getError().getKey());
                extendedKeyCertCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(extendedKeyCertCheckFound);
    }

    @Test
    void noExtendedKeyUsageTimestampingTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
        CertificateWrapper certificateWrapper = new CertificateWrapper(xmlTimestamp.getSigningCertificate().getCertificate());
        certificateWrapper.getExtendedKeyUsages().clear();

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        MultiValuesConstraint validationConstraint = new MultiValuesConstraint();
        validationConstraint.setLevel(Level.FAIL);
        validationConstraint.getId().add("timeStamping");
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setExtendedKeyUsage(validationConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(xmlTimestamp.getId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(xmlTimestamp.getId()));

        XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
        assertNotNull(timestampBBB);
        XmlXCV xcv = timestampBBB.getXCV();
        assertNotNull(xcv);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        boolean extendedKeyUsageCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCGEKU.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCGEKU_ANS.getId(), constraint.getError().getKey());
                extendedKeyUsageCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(extendedKeyUsageCheckFound);

        SimpleReport simpleReport = reports.getSimpleReport();
        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(2, signatureTimestamps.size());

        eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp = signatureTimestamps.get(0);
        assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, timestamp.getSubIndication());
        assertTrue(checkMessageValuePresence(convertMessages(timestamp.getAdESValidationDetails().getError()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGEKU_ANS, MessageTag.SIGNING_CERTIFICATE, MessageTag.TIMESTAMP)));

    }

    @Test
    void fakeCAFailTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_fake_ca.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getCACertificate().setCA(levelConstraint);

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
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICAC_ANS)));

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

        assertEquals(3, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(1);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

        boolean caCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICAC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICAC_ANS.getId(), constraint.getError().getKey());
                caCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(caCheckFound);
    }

    @Test
    void maxPathLengthFailTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_fake_ca.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getCACertificate().setCA(levelConstraint);

        levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getCACertificate().setMaxPathLength(levelConstraint);

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
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICPDV_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICAC_ANS)));

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

        assertEquals(3, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(1);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

        boolean caCheckFound = false;
        boolean maxPathLengthCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICAC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICAC_ANS.getId(), constraint.getWarning().getKey());
                caCheckFound = true;
            } else if (MessageTag.BBB_XCV_ICPDV.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICPDV_ANS.getId(), constraint.getError().getKey());
                maxPathLengthCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(caCheckFound);
        assertTrue(maxPathLengthCheckFound);
    }

    @Test
    void forbiddenCertificateExtensionTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        XmlIdPkixOcspNoCheck ocspNoCheck = new XmlIdPkixOcspNoCheck();
        ocspNoCheck.setOID(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
        ocspNoCheck.setPresent(true);
        xmlCertificate.getCertificateExtensions().add(ocspNoCheck);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
        levelConstraint.setLevel(Level.FAIL);
        levelConstraint.getId().add(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setForbiddenExtensions(levelConstraint);

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
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCCFCE_ANS, Arrays.asList(CertificateExtensionEnum.OCSP_NOCHECK.getOid()))));

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

        assertEquals(3, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

        boolean forbiddenExtensionCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_DCCFCE.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_DCCFCE_ANS.getId(), constraint.getError().getKey());
                forbiddenExtensionCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(forbiddenExtensionCheckFound);
    }

    @Test
    void forbiddenCertificateExtensionWarnTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        XmlIdPkixOcspNoCheck ocspNoCheck = new XmlIdPkixOcspNoCheck();
        ocspNoCheck.setOID(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
        ocspNoCheck.setPresent(true);
        xmlCertificate.getCertificateExtensions().add(ocspNoCheck);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
        levelConstraint.setLevel(Level.WARN);
        levelConstraint.getId().add(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setForbiddenExtensions(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCCFCE_ANS, Arrays.asList(CertificateExtensionEnum.OCSP_NOCHECK.getOid()))));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlXCV xcv = sigBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

        assertEquals(3, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

        boolean forbiddenExtensionCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_DCCFCE.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_DCCFCE_ANS.getId(), constraint.getWarning().getKey());
                forbiddenExtensionCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(forbiddenExtensionCheckFound);
    }

    @Test
    void supportedCriticalCertificateExtensionsTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        XmlKeyUsages keyUsages = new XmlKeyUsages();
        keyUsages.setOID(CertificateExtensionEnum.KEY_USAGE.getOid());
        keyUsages.setCritical(true);
        keyUsages.getKeyUsageBit().add(KeyUsageBit.NON_REPUDIATION);
        xmlCertificate.getCertificateExtensions().add(keyUsages);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
        levelConstraint.setLevel(Level.FAIL);
        levelConstraint.getId().add(CertificateExtensionEnum.KEY_USAGE.getOid());
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setSupportedCriticalExtensions(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCCUCE_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlXCV xcv = sigBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

        assertEquals(3, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

        boolean supportedExtensionsCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_XCV_DCCUCE.getId().equals(constraint.getName().getKey())) {
                supportedExtensionsCheckFound = true;
            }
        }
        assertTrue(supportedExtensionsCheckFound);
    }

    @Test
    void supportedCriticalCertificateExtensionsInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        for (XmlCertificateExtension certificateExtension : xmlCertificate.getCertificateExtensions()) {
            if (certificateExtension instanceof XmlKeyUsages) {
                certificateExtension.setCritical(true);
            }
        }

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
        levelConstraint.setLevel(Level.FAIL);
        levelConstraint.getId().add(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setSupportedCriticalExtensions(levelConstraint);

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
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCCUCE_ANS, Arrays.asList(CertificateExtensionEnum.KEY_USAGE.getOid()))));

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

        assertEquals(3, xcv.getSubXCV().size());
        XmlSubXCV subXCV = xcv.getSubXCV().get(0);
        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

        boolean supportedExtensionsCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_DCCUCE.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_DCCUCE_ANS.getId(), constraint.getError().getKey());
                supportedExtensionsCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(supportedExtensionsCheckFound);
    }

    @Test
    void policyTreeValidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_policy_constraints.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setPolicyTree(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

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

        boolean policyTreeCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_XCV_ICPTV.getId().equals(constraint.getName().getKey())) {
                policyTreeCheckFound = true;
            }
        }
        assertTrue(policyTreeCheckFound);
    }

    @Test
    void policyTreeInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_policy_constraints.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        for (XmlCertificateExtension certificateExtension : xmlCertificate.getCertificateExtensions()) {
            if (certificateExtension instanceof XmlCertificatePolicies) {
                XmlCertificatePolicies xmlCertificatePolicies = (XmlCertificatePolicies) certificateExtension;
                xmlCertificatePolicies.getCertificatePolicy().get(0).setValue("1.2.3.4.5");
                xmlCertificatePolicies.getCertificatePolicy().get(1).setValue("6.7.8.9.0");
            }
        }

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setPolicyTree(levelConstraint);

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
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICPTV_ANS)));

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

        boolean policyTreeCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ICPTV.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICPTV_ANS.getId(), constraint.getError().getKey());
                policyTreeCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(policyTreeCheckFound);
    }

    @Test
    void nameConstraintsValidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_name_constraints.xml"));
        assertNotNull(xmlDiagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setNameConstraints(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

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

        boolean nameConstraintsCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_XCV_DCSBSINC.getId().equals(constraint.getName().getKey())) {
                nameConstraintsCheckFound = true;
            }
        }
        assertTrue(nameConstraintsCheckFound);
    }

    @Test
    void nameConstraintsInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_name_constraints.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        xmlCertificate.getSubjectDistinguishedName().clear();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("C=SK,L=Bratislava,2.5.4.5=#534b2d353033343932130e4e54523837,OU=sep,O=Mini,CN=SR");
        xmlCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setNameConstraints(levelConstraint);

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
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCSBSINC_ANS)));

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

        boolean nameConstraintsCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_DCSBSINC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_DCSBSINC_ANS.getId(), constraint.getError().getKey());
                nameConstraintsCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(nameConstraintsCheckFound);
    }

    @Test
    void nameConstraintsSubjectAltNameInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_name_constraints.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        for (XmlCertificateExtension certificateExtension : xmlCertificate.getCertificateExtensions()) {
            if (CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid().equals(certificateExtension.getOID())) {
                XmlSubjectAlternativeNames subjectAlternativeNames = (XmlSubjectAlternativeNames) certificateExtension;
                subjectAlternativeNames.getSubjectAlternativeName().get(0).setValue("C=SK,L=Bratislava,2.5.4.5=#534b2d353033343932130e4e54523837,OU=sep,O=Mini,CN=SR");
            }
        }

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setNameConstraints(levelConstraint);

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
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCSBSINC_ANS)));

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

        boolean nameConstraintsCheckFound = false;
        for (XmlConstraint constraint : subXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_DCSBSINC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_DCSBSINC_ANS.getId(), constraint.getError().getKey());
                nameConstraintsCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(nameConstraintsCheckFound);
    }

    @Test
    void issuerNameFailLevel() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlCertificate certificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        certificate.getIssuerEntityKey().setSubjectName(false);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setIssuerName(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(sigBBB);

        XmlXCV xcv = sigBBB.getXCV();
        assertNotNull(xcv);
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        boolean issuerNameCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_DCIDNMSDNIC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS.getId(), xmlConstraint.getError().getKey());
                issuerNameCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(issuerNameCheckFound);
    }

    @Test
    void issuerNameWarnLevel() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlCertificate certificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        certificate.getIssuerEntityKey().setSubjectName(false);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setIssuerName(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(sigBBB);

        XmlXCV xcv = sigBBB.getXCV();
        assertNotNull(xcv);
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        boolean issuerNameCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_DCIDNMSDNIC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS.getId(), xmlConstraint.getWarning().getKey());
                issuerNameCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(issuerNameCheckFound);
    }

}
