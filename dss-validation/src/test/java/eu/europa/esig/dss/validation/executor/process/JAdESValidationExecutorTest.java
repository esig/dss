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
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignedAttributesConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void checkJAdESKidValidSigTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_jades_valid.xml"));
        assertNotNull(diagnosticData);

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        SignedAttributesConstraints signedAttributes = validationPolicy.getSignatureConstraints().getSignedAttributes();
        signedAttributes.setKeyIdentifierPresent(levelConstraint);
        signedAttributes.setKeyIdentifierMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void checkJAdESNoKidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_jades_valid.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlFoundCertificates foundCertificates = xmlSignature.getFoundCertificates();
        for (XmlRelatedCertificate relatedCertificate : foundCertificates.getRelatedCertificates()) {
            Iterator<XmlCertificateRef> iterator = relatedCertificate.getCertificateRefs().iterator();
            while (iterator.hasNext()) {
                XmlCertificateRef certificateRef = iterator.next();
                if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRef.getOrigin())) {
                    iterator.remove();
                }
            }
        }

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        SignedAttributesConstraints signedAttributes = validationPolicy.getSignatureConstraints().getSignedAttributes();
        signedAttributes.setKeyIdentifierPresent(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_ICS_ISAKIDP_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

        boolean kidPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertNotNull(constraint.getError());
                assertEquals(MessageTag.BBB_ICS_ISAKIDP_ANS.getId(), constraint.getError().getKey());
                kidPresentCheckFound = true;
            }
        }
        assertTrue(kidPresentCheckFound);
    }

    @Test
    void checkJAdESKidDoesNotMatchTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_jades_valid.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlFoundCertificates foundCertificates = xmlSignature.getFoundCertificates();
        for (XmlRelatedCertificate relatedCertificate : foundCertificates.getRelatedCertificates()) {
            Iterator<XmlCertificateRef> iterator = relatedCertificate.getCertificateRefs().iterator();
            while (iterator.hasNext()) {
                XmlCertificateRef certificateRef = iterator.next();
                if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRef.getOrigin())) {
                    certificateRef.getIssuerSerial().setMatch(false);
                }
            }
        }

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        SignedAttributesConstraints signedAttributes = validationPolicy.getSignatureConstraints().getSignedAttributes();
        signedAttributes.setKeyIdentifierMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_ICS_DKIDVM_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

        boolean kidPresentCheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (MessageTag.BBB_ICS_DKIDVM.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertNotNull(constraint.getError());
                assertEquals(MessageTag.BBB_ICS_DKIDVM_ANS.getId(), constraint.getError().getKey());
                kidPresentCheckFound = true;
            }
        }
        assertTrue(kidPresentCheckFound);
    }

    @Test
    void jadesEcdsaTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_jades_valid.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
        xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA256);
        xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("256");

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getSignedAttributes().setEllipticCurveKeySize(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlFC xmlFC = signatureBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        boolean ellipticCurveCheckFound = false;
        for (XmlConstraint constraint : xmlFC.getConstraint()) {
            if (MessageTag.BBB_FC_IECKSCDA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.SIGNATURE_ALGORITHM_WITH_KEY_SIZE, SignatureAlgorithm.ECDSA_SHA256.getName(), "256"),
                        constraint.getAdditionalInfo());
                ellipticCurveCheckFound = true;
                break;
            }
        }
        assertTrue(ellipticCurveCheckFound);

        checkReports(reports);
    }

    @Test
    void jadesEcdsaInvalidKeySizeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_jades_valid.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
        xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA512);
        xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("256");

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getSignedAttributes().setEllipticCurveKeySize(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS5)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, signatureBBB.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS5)));

        XmlFC xmlFC = signatureBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.FAILED, xmlFC.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, xmlFC.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlFC.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS5)));

        boolean ellipticCurveCheckFound = false;
        for (XmlConstraint constraint : xmlFC.getConstraint()) {
            if (MessageTag.BBB_FC_IECKSCDA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_IECKSCDA_ANS5.getId(), constraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.SIGNATURE_ALGORITHM_WITH_KEY_SIZE, SignatureAlgorithm.ECDSA_SHA512.getName(), "256"),
                        constraint.getAdditionalInfo());
                ellipticCurveCheckFound = true;
                break;
            }
        }
        assertTrue(ellipticCurveCheckFound);

        checkReports(reports);
    }

    @Test
    void jadesEcdsaUnauthorizedDigestAlgoTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_jades_valid.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
        xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA224);
        xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("256");

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getSignedAttributes().setEllipticCurveKeySize(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS4)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, signatureBBB.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS4)));

        XmlFC xmlFC = signatureBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.FAILED, xmlFC.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, xmlFC.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlFC.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS4)));

        boolean ellipticCurveCheckFound = false;
        for (XmlConstraint constraint : xmlFC.getConstraint()) {
            if (MessageTag.BBB_FC_IECKSCDA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_IECKSCDA_ANS4.getId(), constraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.SIGNATURE_ALGORITHM_WITH_KEY_SIZE, SignatureAlgorithm.ECDSA_SHA224.getName(), "256"),
                        constraint.getAdditionalInfo());
                ellipticCurveCheckFound = true;
                break;
            }
        }
        assertTrue(ellipticCurveCheckFound);

        checkReports(reports);
    }

    @Test
    void jadesRsaTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_jades_valid.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.RSA);
        xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA512);
        xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("2048");

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getSignedAttributes().setEllipticCurveKeySize(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlFC xmlFC = signatureBBB.getFC();
        assertNotNull(xmlFC);
        assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

        boolean ellipticCurveCheckFound = false;
        for (XmlConstraint constraint : xmlFC.getConstraint()) {
            if (MessageTag.BBB_FC_IECKSCDA.getId().equals(constraint.getName().getKey())) {
                ellipticCurveCheckFound = true;
                break;
            }
        }
        assertFalse(ellipticCurveCheckFound);

        checkReports(reports);
    }

}
