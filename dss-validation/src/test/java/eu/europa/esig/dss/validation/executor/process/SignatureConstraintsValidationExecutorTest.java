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
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.SignedAttributesConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureConstraintsValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void sigConstraintFailure() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig_constraint_failure.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(0, detailedReport.getTimestampIds().size());

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void signingCertificateNotFoundWithFailLevel() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/signing_certificate_not_found.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        validationPolicy.getCryptographic().getAlgoExpirationDate().setLevel(Level.WARN);

        SignedAttributesConstraints signedAttributes = validationPolicy.getSignatureConstraints().getSignedAttributes();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signedAttributes.setSigningCertificatePresent(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        Date currentTime = sdf.parse("04/05/2016 18:55:00");
        executor.setCurrentTime(currentTime);

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(0, detailedReport.getTimestampIds().size());

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
    }

    @Test
    void signingCertificateNotFoundWithCryptoCheck() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/signing_certificate_not_found.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        Date currentTime = sdf.parse("04/05/2016 18:55:00");
        executor.setCurrentTime(currentTime);

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(0, detailedReport.getTimestampIds().size());

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
    }

    @Test
    void noSigningTime() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/no-signing-date.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void signedPropertiesMissedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/signedProperties_missed.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlSAV sav = signatureBBB.getSAV();
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

        checkReports(reports);
    }

    @Test
    void signedPropertiesMissedNotStrictPolicyTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/signedProperties_missed.xml"));
        assertNotNull(diagnosticData);

        LevelConstraint passLevel = new LevelConstraint();
        passLevel.setLevel(Level.WARN);
        ValidationPolicy policy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        SignatureConstraints signatureConstraints = policy.getSignatureConstraints();
        signatureConstraints.getSignedAttributes().setMessageDigestOrSignedPropertiesPresent(passLevel);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(policy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertNull(simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<Message> warnings = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId());
        assertEquals(1, warnings.size());
        assertTrue(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.BBB_SAV_ISQPMDOSPP_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlSAV sav = signatureBBB.getSAV();
        assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void referenceDuplicateTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/diag_data_xsw_attack.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlFC fc = bbb.getFC();
        assertNotNull(fc);

        boolean referenceDuplicationCheckExecuted = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            if (MessageTag.BBB_FC_ISRIA.name().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_ISRIA_ANS.name(), constraint.getError().getKey());
                assertTrue(Utils.isStringNotBlank(constraint.getAdditionalInfo()));
                referenceDuplicationCheckExecuted = true;
            }
        }
        assertTrue(referenceDuplicationCheckExecuted);
    }

}
