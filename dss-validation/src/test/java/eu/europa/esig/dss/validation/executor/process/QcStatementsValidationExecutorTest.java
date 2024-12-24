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

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2QcInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcCompliance;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcEuLimitValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcSSCD;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRoleOfPSP;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QcStatementsValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void qcComplianceTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        certificateConstraints.setQcCompliance(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCC_ANS)));

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlQcCompliance xmlQcCompliance = new XmlQcCompliance();
        xmlQcCompliance.setPresent(true);
        xmlQcStatements.setQcCompliance(xmlQcCompliance);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void qcEuLimitValueCurrencyTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlQcEuLimitValue xmlQcEuLimitValue = new XmlQcEuLimitValue();
        xmlQcEuLimitValue.setCurrency("AUD");
        xmlQcStatements.setQcEuLimitValue(xmlQcEuLimitValue);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue("EUR");
        certificateConstraints.setQcEuLimitValueCurrency(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCLVHAC_ANS)));

        xmlQcEuLimitValue.setCurrency("EUR");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void minQcEuLimitValueTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlQcEuLimitValue xmlQCLimitValue = new XmlQcEuLimitValue();
        xmlQCLimitValue.setAmount(1000);
        xmlQCLimitValue.setExponent(0);
        xmlQcStatements.setQcEuLimitValue(xmlQCLimitValue);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(500000);
        certificateConstraints.setMinQcEuLimitValue(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCLVA_ANS)));

        xmlQCLimitValue.setExponent(3);

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void minQcEuRetentionPeriodTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        xmlQcStatements.setQcEuRetentionPeriod(3);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(5);
        certificateConstraints.setMinQcEuRetentionPeriod(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCERPA_ANS)));

        xmlQcStatements.setQcEuRetentionPeriod(10);

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void qcSSCDTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlQcSSCD xmlQcSSCD = new XmlQcSSCD();
        xmlQcSSCD.setPresent(false);
        xmlQcStatements.setQcSSCD(xmlQcSSCD);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        certificateConstraints.setQcSSCD(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICSQCSSCD_ANS)));

        xmlQcSSCD.setPresent(true);

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void qcEuPDSLocationTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlLangAndValue langAndValue = new XmlLangAndValue();
        langAndValue.setLang("en");
        langAndValue.setValue("https://repository.eid.lux.lu");
        xmlQcStatements.getQcEuPDS().add(langAndValue);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("https://repository.eid.belgium.be");
        certificateConstraints.setQcEuPDSLocation(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCPDSLA_ANS)));

        langAndValue.setValue("https://repository.eid.belgium.be");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void qcTypeTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlOID xmlOID = new XmlOID();
        xmlOID.setValue("0.4.0.1862.1.6.2");
        xmlOID.setDescription("qc-type-eseal");
        xmlQcStatements.setQcTypes(Arrays.asList(xmlOID));
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("qc-type-esign");
        certificateConstraints.setQcType(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCTA_ANS)));

        xmlOID.setValue("0.4.0.1862.1.6.1");
        xmlOID.setDescription("qc-type-esign");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void qcCCLegislationTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        // Id list empty (EU certificate expected)
        certificateConstraints.setQcLegislationCountryCodes(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        xmlQcStatements.setQcCClegislation(Arrays.asList("FR"));

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCDCQCCLCEC_ANS_EU)));

        constraint.getId().add("LU");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCDCQCCLCEC_ANS)));

        constraint.getId().add("FR");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void semanticsIdentifierForLegalPersonTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription("Semantics identifier for natural person");
        xmlOID.setValue("0.4.0.194121.1.1");
        xmlQcStatements.setSemanticsIdentifier(xmlOID);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("0.4.0.194121.1.2");
        constraint.setLevel(Level.FAIL);
        certificateConstraints.setSemanticsIdentifier(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCSCSIA_ANS)));

        xmlOID.setDescription("Semantics identifier for legal person");
        xmlOID.setValue("0.4.0.194121.1.2");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void semanticsIdentifierForNaturalPersonTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription("Semantics identifier for legal person");
        xmlOID.setValue("0.4.0.194121.1.2");
        xmlQcStatements.setSemanticsIdentifier(xmlOID);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("0.4.0.194121.1.1");
        constraint.getId().add("0.4.0.194121.1.3");
        constraint.setLevel(Level.FAIL);
        certificateConstraints.setSemanticsIdentifier(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCSCSIA_ANS)));

        xmlOID.setDescription("Semantics identifier for natural person");
        xmlOID.setValue("0.4.0.194121.1.1");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void semanticsIdentifierForEIDASLegalPersonTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription("Semantics identifier for eIDAS natural person");
        xmlOID.setValue("0.4.0.194121.1.3");
        xmlQcStatements.setSemanticsIdentifier(xmlOID);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("0.4.0.194121.1.2");
        constraint.getId().add("0.4.0.194121.1.4");
        constraint.setLevel(Level.FAIL);
        certificateConstraints.setSemanticsIdentifier(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCSCSIA_ANS)));

        xmlOID.setDescription("Semantics identifier for eIDAS legal person");
        xmlOID.setValue("0.4.0.194121.1.4");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void semanticsIdentifierForEIDASNaturalPersonTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription("Semantics identifier for eIDAS legal person");
        xmlOID.setValue("0.4.0.194121.1.4");
        xmlQcStatements.setSemanticsIdentifier(xmlOID);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("0.4.0.194121.1.3");
        constraint.setLevel(Level.FAIL);
        certificateConstraints.setSemanticsIdentifier(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCSCSIA_ANS)));

        xmlOID.setDescription("Semantics identifier for eIDAS natural person");
        xmlOID.setValue("0.4.0.194121.1.3");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void ps2dQcRolesOfPSPTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlPSD2QcInfo xmlPSD2Info = new XmlPSD2QcInfo();
        XmlRoleOfPSP roleOfPSP = new XmlRoleOfPSP();
        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription("psp-as");
        xmlOID.setValue("0.4.0.19495.1.1");
        roleOfPSP.setOid(xmlOID);
        xmlPSD2Info.getRolesOfPSP().add(roleOfPSP);
        xmlQcStatements.setPSD2QcInfo(xmlPSD2Info);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("psp-pi");
        certificateConstraints.setPSD2QcTypeRolesOfPSP(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCRA_ANS)));

        xmlOID.setDescription("psp-pi");
        xmlOID.setValue("0.4.0.19495.1.2");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void ps2dQcCANameTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlPSD2QcInfo xmlPSD2Info = new XmlPSD2QcInfo();
        xmlPSD2Info.setNcaName("NBB");
        xmlQcStatements.setPSD2QcInfo(xmlPSD2Info);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("CSSF");
        certificateConstraints.setPSD2QcCompetentAuthorityName(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCNA_ANS)));

        xmlPSD2Info.setNcaName("CSSF");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void ps2dQcCAIdTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate();
        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        XmlPSD2QcInfo xmlPSD2Info = new XmlPSD2QcInfo();
        xmlPSD2Info.setNcaId("BE-NBB");
        xmlQcStatements.setPSD2QcInfo(xmlPSD2Info);
        signingCertificate.getCertificateExtensions().add(xmlQcStatements);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("LU-CSSF");
        certificateConstraints.setPSD2QcCompetentAuthorityId(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCIA_ANS)));

        xmlPSD2Info.setNcaId("LU-CSSF");

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

}
