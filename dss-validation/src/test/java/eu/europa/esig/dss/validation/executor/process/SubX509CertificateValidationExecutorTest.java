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
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SubX509CertificateValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void surnameNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setSurname("Freeman");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Freeman");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setSurname(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void surnameNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setSurname("Freeman");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Di Caprio");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setSurname(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGSURN_ANS)));
    }

    @Test
    void givennameNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setGivenName("Alice");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Alice");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setGivenName(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void givennameNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setGivenName("Alice");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Bob");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setGivenName(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGGIVEN_ANS)));
    }

    @Test
    void commonnameNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setCommonName("TestName");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("TestName");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setCommonName(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void commonnameNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setCommonName("TestName");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("ProdName");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setCommonName(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGCOMMONN_ANS)));
    }

    @Test
    void pseudonymNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setPseudonym("Pseudonym");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Pseudonym");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setPseudonym(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void pseudonymNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setPseudonym("Pseudonym");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Anonymous");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setPseudonym(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGPSEUDO_ANS)));
    }

    @Test
    void titleNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setTitle("CEO");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("CEO");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setTitle(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void titleNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setTitle("CEO");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("CFO");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setTitle(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGTITLE_ANS)));
    }

    @Test
    void emailNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setEmail("valid@email.com");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("valid@email.com");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setEmail(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void emailNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setEmail("invalid@email.com");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("valid@email.com");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setEmail(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGEMAIL_ANS)));
    }

    @Test
    void countryNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("LU");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setCountry(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void countryNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("FR");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setCountry(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGCOUN_ANS)));
    }

    @Test
    void localityNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setLocality("Kehlen");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Kehlen");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setLocality(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void localityNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setLocality("Kehlen");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Strassen");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setLocality(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGLOC_ANS)));
    }

    @Test
    void stateNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setState("Kehlen");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Kehlen");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setState(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void stateNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setState("Kehlen");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Strassen");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setState(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGST_ANS)));
    }

    @Test
    void organizationIdentifierNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setOrganizationIdentifier("1215452");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("1215452");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationIdentifier(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void organizationIdentifierNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setOrganizationIdentifier("1215452");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("5215351");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationIdentifier(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGORGAI_ANS)));
    }

    @Test
    void organizationUnitNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setOrganizationalUnit("Org Unit 1");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Org Unit 1");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationUnit(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void organizationUnitNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setOrganizationalUnit("Org Unit 1");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Org Unit 2");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationUnit(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGORGAU_ANS)));
    }

    @Test
    void organizationNameValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setOrganizationName("Nowina Solutions");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Nowina Solutions");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationName(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void organizationNameInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
        xmlCertificate.setOrganizationName("Nowina Solutions");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        ValidationPolicy defaultPolicy = loadDefaultPolicy();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add("Oldwina Solutions");
        multiValuesConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationName(multiValuesConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGORGAN_ANS)));
    }

}
