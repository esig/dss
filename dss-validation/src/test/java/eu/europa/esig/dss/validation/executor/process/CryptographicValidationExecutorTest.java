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
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.SignedAttributesConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptographicValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void dss1791() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/algo.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // TODO: Etsi Validation Report

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        assertNull(simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));
        assertNotNull(simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void dss1791Two() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/algo2.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // TODO: Etsi Validation Report

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void rsa1023() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/rsa1023.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        Date validationDate = diagnosticData.getValidationDate();
        executor.setCurrentTime(validationDate);

        Reports reports = executor.execute();
        DetailedReport detailedReport = reports.getDetailedReport();

        boolean foundWeakAlgo = false;
        List<String> revocationIds = detailedReport.getRevocationIds();
        for (String revocationId : revocationIds) {
            XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(revocationId);
            XmlSAV sav = bbb.getSAV();
            XmlCryptographicValidation cryptographicValidation = sav.getCryptographicValidation();
            if (!cryptographicValidation.isSecure()) {
                foundWeakAlgo = true;
                assertTrue(validationDate.after(cryptographicValidation.getNotAfter()));
            }
        }
        assertTrue(foundWeakAlgo);

        SimpleReport simpleReport = reports.getSimpleReport();

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicBuildingBlocksSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);

        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());

        XmlPCV pcv = signatureBBB.getPCV();
        assertNull(pcv);

        XmlVTS vts = signatureBBB.getVTS();
        assertNull(vts);

        XmlPSV psv = signatureBBB.getPSV();
        assertNull(psv);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void cryptoNoPOETest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_crypto_no_poe.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void dss1635Test() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss-1635-diag-data.xml"));
        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        ValidationPolicy defaultPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        List<Algo> algos = defaultPolicy.getCryptographic().getAlgoExpirationDate().getAlgos();
        for (Algo algo : algos) {
            if ("SHA1".equals(algo.getValue())) {
                algo.setDate("2014-01-01");
                break;
            }
        }
        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        // current year returns a first day
        for (Algo algo : algos) {
            if ("SHA1".equals(algo.getValue())) {
                algo.setDate("2013-01-01");
                break;
            }
        }

        executor.setValidationPolicy(defaultPolicy);
        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void etsiTS119312V151UpdateTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss-1635-diag-data.xml"));
        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        // before ETSI TS 102 176-1 (Historical) V2.0.0 (expiration at 2009)
        Calendar calendar = Calendar.getInstance();
        calendar.set(2008, Calendar.JANUARY, 1);
        diagnosticData.getUsedTimestamps().get(0).setProductionTime(calendar.getTime());

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        // before ETSI TS 119 312 V1.5.1 (expiration at 2012-08-01)
        calendar = Calendar.getInstance();
        calendar.set(2012, Calendar.JANUARY, 1);
        diagnosticData.getUsedTimestamps().get(0).setProductionTime(calendar.getTime());

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        // at ETSI TS 119 312 V1.5.1 (expiration at 2012-08-01)
        calendar = Calendar.getInstance();
        calendar.set(2012, Calendar.AUGUST, 1);
        diagnosticData.getUsedTimestamps().get(0).setProductionTime(calendar.getTime());

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        // after ETSI TS 119 312 V1.5.1 (expiration at 2012-08-01)
        calendar = Calendar.getInstance();
        calendar.set(2013, Calendar.JANUARY, 1);
        diagnosticData.getUsedTimestamps().get(0).setProductionTime(calendar.getTime());

        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void rsa2047Test() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-1938/rsa2047-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void rsa2047RevokedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-1938/rsa2047-diag-data-revoked.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertNotNull(validationProcessBasicSignature.getTitle());
        assertNotNull(validationProcessBasicSignature.getProofOfExistence());

        boolean x509CVCheckFound = false;
        boolean x509RevokedCheckFound = false;
        boolean tstAfterRevocationTimeCheckFound = false;
        boolean basicSignatureValidationCheckFound = false;
        for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
            if (MessageTag.BSV_IXCVRC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                x509CVCheckFound = true;
            } else if (MessageTag.BSV_ISCRAVTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                x509RevokedCheckFound = true;
            } else if (MessageTag.BSV_ICTGTNASCRT.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                tstAfterRevocationTimeCheckFound = true;
            } else if (MessageTag.ADEST_ROBVPIIC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                basicSignatureValidationCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(x509CVCheckFound);
        assertTrue(x509RevokedCheckFound);
        assertTrue(tstAfterRevocationTimeCheckFound);
        assertTrue(basicSignatureValidationCheckFound);

        assertFalse(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ADEST_ROBVPIIC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.BSV_ICTGTNASCRT_ANS)));
    }

    @Test
    void rsa2047ExpiredTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-1938/rsa2047-diag-data-expired.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.EXPIRED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertNotNull(validationProcessBasicSignature.getTitle());
        assertNotNull(validationProcessBasicSignature.getProofOfExistence());

        boolean x509CVCheckFound = false;
        boolean x509ExpiredCheckFound = false;
        boolean tstAfterExpirationTimeCheckFound = false;
        boolean basicSignatureValidationCheckFound = false;
        for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
            if (MessageTag.BSV_IXCVRC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                x509CVCheckFound = true;
            } else if (MessageTag.BSV_IVTAVRSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                x509ExpiredCheckFound = true;
            } else if (MessageTag.BSV_ICTGTNASCET.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                tstAfterExpirationTimeCheckFound = true;
            } else if (MessageTag.ADEST_ROBVPIIC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                basicSignatureValidationCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(x509CVCheckFound);
        assertTrue(x509ExpiredCheckFound);
        assertTrue(tstAfterExpirationTimeCheckFound);
        assertTrue(basicSignatureValidationCheckFound);

        assertFalse(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ADEST_ROBVPIIC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.BSV_ICTGTNASCET_ANS)));
    }

    @Test
    void rsa2047CryptoConstraintFailureTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/DSS-1938/rsa2047-diag-data-crypto-constraint-failure.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void md5Test() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/md5-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        // validation on 2005-01-20
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void md5ValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/md5-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        // validation on 2004-01-20
        Date validationDate = diagnosticData.getValidationDate();
        Calendar cal = Calendar.getInstance();
        cal.setTime(validationDate);
        cal.add(Calendar.YEAR, -1);
        executor.setCurrentTime(cal.getTime());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void digestMatcherCryptoTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        List<XmlDigestMatcher> digestMatchers = xmlSignature.getDigestMatchers();
        digestMatchers.get(1).setDigestMethod(DigestAlgorithm.SHA1);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        String tstId = detailedReport.getTimestampIds().get(0);
        assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(tstId));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlSAV sav = signatureBBB.getSAV();
        assertEquals(1, sav.getConclusion().getErrors().size());

        XmlCryptographicValidation cryptographicValidation = sav.getCryptographicValidation();
        assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.forXML(cryptographicValidation.getAlgorithm().getUri()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_SIGND_PRT)));
    }

    @Test
    void tstDigestMatcherCryptoTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTimestamp xmlTimestamp = diagnosticData.getUsedTimestamps().get(0);
        List<XmlDigestMatcher> digestMatchers = xmlTimestamp.getDigestMatchers();
        digestMatchers.get(0).setDigestMethod(DigestAlgorithm.SHA1);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(xmlTimestamp.getId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicTimestampValidationSubIndication(xmlTimestamp.getId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
        XmlSAV sav = signatureBBB.getSAV();
        assertEquals(1, sav.getConclusion().getErrors().size());

        XmlCryptographicValidation cryptographicValidation = sav.getCryptographicValidation();
        assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.forXML(cryptographicValidation.getAlgorithm().getUri()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertFalse(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_MESS_IMP)));
    }

    @Test
    void messageDigestWithSha1WithTstTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/message-digest-sha1-with-tst.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
    }

    @Test
    void messageDigestWithSha1WithBrokenTstTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/message-digest-sha1-with-tst.xml"));
        assertNotNull(diagnosticData);

        XmlTimestamp xmlTimestamp = diagnosticData.getUsedTimestamps().get(0);
        xmlTimestamp.getBasicSignature().setSignatureIntact(false);
        xmlTimestamp.getBasicSignature().setSignatureValid(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
    }

    @Test
    void dsaWith2048KeySizeTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_dsa_signature.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void dsaWith1024KeySizeTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_dsa_signature.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("1024");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_AKSNR,
                        EncryptionAlgorithm.DSA.getName(), "1024", MessageTag.ACCM_POS_SIG_SIG)));
    }

    @Test
    void signCertRefWithSHA1Test() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        List<XmlRelatedCertificate> relatedCertificates = xmlSignature.getFoundCertificates().getRelatedCertificates();
        for (XmlRelatedCertificate relatedCertificate : relatedCertificates) {
            List<XmlCertificateRef> certificateRefs = relatedCertificate.getCertificateRefs();
            for (XmlCertificateRef certificateRef : certificateRefs) {
                if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
                    certificateRef.getDigestAlgoAndValue().setDigestMethod(DigestAlgorithm.SHA1);
                }
            }
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signedAttributes.setSigningCertificateDigestAlgorithm(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1.getName(), MessageTag.ACCM_POS_SIG_CERT_REF)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());

        boolean signRefDACheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(constraint.getName().getValue())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), constraint.getError().getKey());
                signRefDACheckFound = true;
            }
        }
        assertTrue(signRefDACheckFound);

        checkReports(reports);
    }

    @Test
    void signCertRefWithSHA1WarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        List<XmlRelatedCertificate> relatedCertificates = xmlSignature.getFoundCertificates().getRelatedCertificates();
        for (XmlRelatedCertificate relatedCertificate : relatedCertificates) {
            List<XmlCertificateRef> certificateRefs = relatedCertificate.getCertificateRefs();
            for (XmlCertificateRef certificateRef : certificateRefs) {
                if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
                    certificateRef.getDigestAlgoAndValue().setDigestMethod(DigestAlgorithm.SHA1);
                }
            }
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signedAttributes.setSigningCertificateDigestAlgorithm(levelConstraint);

        CryptographicConstraint cryptographic = validationPolicy.getCryptographic();
        AlgoExpirationDate algoExpirationDate = cryptographic.getAlgoExpirationDate();
        algoExpirationDate.setLevel(Level.WARN);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1.getName(), MessageTag.ACCM_POS_SIG_CERT_REF)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

        boolean signRefDACheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(constraint.getName().getValue())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), constraint.getWarning().getKey());
                signRefDACheckFound = true;
            }
        }
        assertTrue(signRefDACheckFound);

        checkReports(reports);
    }

    @Test
    void signCertRefWarnWithSHA1Test() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        List<XmlRelatedCertificate> relatedCertificates = xmlSignature.getFoundCertificates().getRelatedCertificates();
        for (XmlRelatedCertificate relatedCertificate : relatedCertificates) {
            List<XmlCertificateRef> certificateRefs = relatedCertificate.getCertificateRefs();
            for (XmlCertificateRef certificateRef : certificateRefs) {
                if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
                    certificateRef.getDigestAlgoAndValue().setDigestMethod(DigestAlgorithm.SHA1);
                }
            }
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        signedAttributes.setSigningCertificateDigestAlgorithm(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1.getName(), MessageTag.ACCM_POS_SIG_CERT_REF)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

        boolean signRefDACheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(constraint.getName().getValue())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), constraint.getWarning().getKey());
                signRefDACheckFound = true;
            }
        }
        assertTrue(signRefDACheckFound);

        checkReports(reports);
    }

    @Test
    void signCertRefWithSHA1WithPOETest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/universign.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getValidationPolicy(
                new File("src/test/resources/diag-data/policy/all-constraint-specified-policy.xml"));
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signedAttributes.setSigningCertificateDigestAlgorithm(levelConstraint);

        CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getCACertificate();
        CryptographicConstraint cryptographic = signingCertificate.getCryptographic();
        AlgoExpirationDate algoExpirationDate = cryptographic.getAlgoExpirationDate();
        for (Algo algo : algoExpirationDate.getAlgos()) {
            if (DigestAlgorithm.SHA1.getName().equals(algo.getValue())) {
                algo.setDate("2020-1-1");
            }
        }

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());

        boolean signRefDACheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(constraint.getName().getValue())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), constraint.getError().getKey());
                signRefDACheckFound = true;
            }
        }
        assertTrue(signRefDACheckFound);

        checkReports(reports);
    }

    @Test
    void signCertRefWithSHA1AcceptSignCertPolicyTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/universign.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getValidationPolicy(
                new File("src/test/resources/diag-data/policy/all-constraint-specified-policy.xml"));
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signedAttributes.setSigningCertificateDigestAlgorithm(levelConstraint);

        CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        CryptographicConstraint cryptographic = signingCertificate.getCryptographic();
        AlgoExpirationDate algoExpirationDate = cryptographic.getAlgoExpirationDate();
        for (Algo algo : algoExpirationDate.getAlgos()) {
            if (DigestAlgorithm.SHA1.getName().equals(algo.getValue())) {
                algo.setDate("2020-1-1");
            }
        }

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void signCertRefDigestCheckOnLTATest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-1453/diag-data-lta-dss.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signedAttributes.setSigningCertificateDigestAlgorithm(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1.getName(), MessageTag.ACCM_POS_SIG_CERT_REF)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlSAV sav = signatureBBB.getSAV();
        assertNotNull(sav);
        assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());

        boolean signRefDACheckFound = false;
        for (XmlConstraint constraint : sav.getConstraint()) {
            if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(constraint.getName().getValue())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), constraint.getError().getKey());
                signRefDACheckFound = true;
            }
        }
        assertTrue(signRefDACheckFound);

        checkReports(reports);
    }

    @Test
    void signatureWithMD2Test() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.MD2);

        xmlSignature.getFoundTimestamps().clear();
        diagnosticData.getUsedTimestamps().clear();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BSV_ICTGTNACCET_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureBBB.getConclusion().getSubIndication());

        XmlSAV signatureSAV = signatureBBB.getSAV();
        assertNotNull(signatureSAV);
        assertEquals(Indication.INDETERMINATE, signatureSAV.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureSAV.getConclusion().getSubIndication());

        boolean cryptoCheckFound = false;
        for (XmlConstraint constraint : signatureSAV.getConstraint()) {
            if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG),
                        constraint.getError().getValue());
                cryptoCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(cryptoCheckFound);

        assertEquals(1, detailedReport.getSignatures().size());
        XmlValidationProcessBasicSignature validationProcessBasicSignature = detailedReport.getSignatures().get(0).getValidationProcessBasicSignature();
        assertNotNull(validationProcessBasicSignature);
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());

        boolean contentTstBasicValidationFound = false;
        boolean checkAgainstContentTstFound = false;
        for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                contentTstBasicValidationFound = true;
            } else if (MessageTag.BSV_ICTGTNACCET.getId().equals(constraint.getName().getKey())) {
                checkAgainstContentTstFound = true;
            }
        }
        assertFalse(contentTstBasicValidationFound);
        assertFalse(checkAgainstContentTstFound);

        checkReports(reports);
    }

    @Test
    void signatureWithMD2AndContentTstTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.MD2);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BSV_ICTGTNACCET_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureBBB.getConclusion().getSubIndication());

        XmlSAV signatureSAV = signatureBBB.getSAV();
        assertNotNull(signatureSAV);
        assertEquals(Indication.INDETERMINATE, signatureSAV.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureSAV.getConclusion().getSubIndication());

        boolean cryptoCheckFound = false;
        for (XmlConstraint constraint : signatureSAV.getConstraint()) {
            if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG),
                        constraint.getError().getValue());
                cryptoCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(cryptoCheckFound);

        assertEquals(1, detailedReport.getSignatures().size());
        XmlValidationProcessBasicSignature validationProcessBasicSignature = detailedReport.getSignatures().get(0).getValidationProcessBasicSignature();
        assertNotNull(validationProcessBasicSignature);
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE, validationProcessBasicSignature.getConclusion().getSubIndication());

        boolean contentTstBasicValidationFound = false;
        boolean checkAgainstContentTstFound = false;
        for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                contentTstBasicValidationFound = true;
            } else if (MessageTag.BSV_ICTGTNACCET.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BSV_ICTGTNACCET_ANS.getId(), constraint.getError().getKey());
                checkAgainstContentTstFound = true;
            }
        }
        assertTrue(contentTstBasicValidationFound);
        assertTrue(checkAgainstContentTstFound);

        checkReports(reports);
    }

    @Test
    void signatureWithMD2AndSHA3with224ContentTstTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.MD2);

        XmlTimestamp xmlTimestamp = xmlSignature.getFoundTimestamps().get(0).getTimestamp();
        xmlTimestamp.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA3_224);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BSV_ICTGTNACCET_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS)));

        eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp contentTst = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0);
        assertEquals(Indication.INDETERMINATE, contentTst.getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, contentTst.getSubIndication());
        assertTrue(checkMessageValuePresence(convertMessages(contentTst.getAdESValidationDetails().getError()),
                i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.SHA3_224.getName(), MessageTag.ACCM_POS_TST_SIG)));

        DetailedReport detailedReport = reports.getDetailedReport();

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureBBB.getConclusion().getSubIndication());

        XmlSAV signatureSAV = signatureBBB.getSAV();
        assertNotNull(signatureSAV);
        assertEquals(Indication.INDETERMINATE, signatureSAV.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureSAV.getConclusion().getSubIndication());

        boolean cryptoCheckFound = false;
        boolean cntTstCheckFound = false;
        for (XmlConstraint constraint : signatureSAV.getConstraint()) {
            if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG),
                        constraint.getError().getValue());
                cryptoCheckFound = true;
            } else if (MessageTag.BBB_SAV_ICTVS.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.BBB_SAV_ICTVS_ANS), constraint.getWarning().getValue());
                cntTstCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(cryptoCheckFound);
        assertTrue(cntTstCheckFound);

        XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
        assertNotNull(timestampBBB);
        assertEquals(Indication.INDETERMINATE, timestampBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, timestampBBB.getConclusion().getSubIndication());

        XmlSAV timestampSAV = timestampBBB.getSAV();
        assertNotNull(timestampSAV);
        assertEquals(Indication.INDETERMINATE, timestampSAV.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, timestampSAV.getConclusion().getSubIndication());

        boolean cryptoCheckForTstFound = false;
        for (XmlConstraint constraint : timestampSAV.getConstraint()) {
            if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.SHA3_224.getName(), MessageTag.ACCM_POS_TST_SIG),
                        constraint.getError().getValue());
                cryptoCheckForTstFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(cryptoCheckForTstFound);

        assertEquals(1, detailedReport.getSignatures().size());
        XmlValidationProcessBasicSignature validationProcessBasicSignature = detailedReport.getSignatures().get(0).getValidationProcessBasicSignature();
        assertNotNull(validationProcessBasicSignature);
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());

        boolean contentTstBasicValidationFound = false;
        boolean checkAgainstContentTstFound = false;
        for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                contentTstBasicValidationFound = true;
            } else if (MessageTag.BSV_ICTGTNACCET.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BSV_ICTGTNACCET_ANS.getId(), constraint.getError().getKey());
                checkAgainstContentTstFound = true;
            }
        }
        assertTrue(contentTstBasicValidationFound);
        assertFalse(checkAgainstContentTstFound);

        checkReports(reports);
    }

    @Test
    void xadesRsaPssFailureTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.RSASSA_PSS);
        xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("1872");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureBBB.getConclusion().getSubIndication());

        checkReports(reports);
    }

    @Test
    void xadesRsaPssLegacyValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.RSASSA_PSS);
        xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("2048");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void xadesRsaPssValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.RSASSA_PSS);
        xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("3072");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void xadesEcdsaTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
        xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA512);
        xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("256");

        ValidationPolicy validationPolicy = loadDefaultPolicy();

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
                ellipticCurveCheckFound = true;
                break;
            }
        }
        assertFalse(ellipticCurveCheckFound);

        checkReports(reports);
    }

}
