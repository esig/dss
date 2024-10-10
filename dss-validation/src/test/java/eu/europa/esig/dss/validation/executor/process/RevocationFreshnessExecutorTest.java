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
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrusted;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.policy.jaxb.TimeUnit;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RevocationFreshnessExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void thisUpdateBeforeBestSignatureTimeNoRevocationFreshnessCheckTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_thisUpdate_before_sigTst.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        CertificateConstraints signingCertificate = signatureConstraints.getBasicSignatureConstraints().getSigningCertificate();
        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setUnit(TimeUnit.SECONDS);
        timeConstraint.setValue(0);
        timeConstraint.setLevel(Level.IGNORE);
        signingCertificate.setRevocationFreshness(timeConstraint);

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
    void thisUpdateBeforeBestSignatureTimeWithRevocationFreshnessCheckTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_thisUpdate_before_sigTst.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        CertificateConstraints signingCertificate = signatureConstraints.getBasicSignatureConstraints().getSigningCertificate();
        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setUnit(TimeUnit.SECONDS);
        timeConstraint.setValue(0);
        timeConstraint.setLevel(Level.FAIL);
        signingCertificate.setRevocationFreshness(timeConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        List<XmlSubXCV> subXCV = xcv.getSubXCV();
        assertEquals(2, subXCV.size());

        XmlSubXCV xmlSubXCV = subXCV.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, xmlSubXCV.getConclusion().getSubIndication());

        XmlCRS crs = xmlSubXCV.getCRS();
        assertNotNull(crs);
        assertEquals(1, crs.getRAC().size());

        XmlRFC rfc = xmlSubXCV.getRFC();
        assertNotNull(rfc);
        assertEquals(Indication.INDETERMINATE, rfc.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, rfc.getConclusion().getSubIndication());

        boolean revocationFreshCheckFound = false;
        for (XmlConstraint constraint : rfc.getConstraint()) {
            if (MessageTag.BBB_RFC_IRIF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                revocationFreshCheckFound = true;
            }
        }
        assertTrue(revocationFreshCheckFound);

        checkReports(reports);
    }

    @Test
    void oldAndFreshOCSPsRevocationFreshnessCheckTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_with_old_and_fresh_ocsp.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        CertificateConstraints signingCertificate = signatureConstraints.getBasicSignatureConstraints().getSigningCertificate();
        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setUnit(TimeUnit.SECONDS);
        timeConstraint.setValue(0);
        timeConstraint.setLevel(Level.FAIL);
        signingCertificate.setRevocationFreshness(timeConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        List<XmlSubXCV> subXCV = xcv.getSubXCV();
        assertEquals(2, subXCV.size());

        XmlSubXCV xmlSubXCV = subXCV.get(0);
        assertEquals(Indication.PASSED, xmlSubXCV.getConclusion().getIndication());

        XmlCRS crs = xmlSubXCV.getCRS();
        assertNotNull(crs);
        assertEquals(2, crs.getRAC().size());

        XmlRFC rfc = xmlSubXCV.getRFC();
        assertNotNull(rfc);
        assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

        boolean revocationFreshCheckFound = false;
        for (XmlConstraint constraint : rfc.getConstraint()) {
            if (MessageTag.BBB_RFC_IRIF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                revocationFreshCheckFound = true;
            }
        }
        assertTrue(revocationFreshCheckFound);

        checkReports(reports);
    }

    @Test
    void checkMinAndMaxUpdateValidLTTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_xades_level_lta_revo_freshness.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        CertificateConstraints caCertificateConstraints = signatureConstraints
                .getBasicSignatureConstraints().getCACertificate();
        caCertificateConstraints.getRevocationFreshness().setLevel(Level.FAIL);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        List<XmlSignature> signatures = diagnosticData.getSignatures();
        assertEquals(1, signatures.size());
        XmlSignature xmlSignature = signatures.get(0);
        XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
        assertNotNull(signingCertificate);
        XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
        assertNotNull(caCertificate);
        List<XmlCertificateRevocation> revocations = caCertificate.getCertificate().getRevocations();
        assertEquals(1, revocations.size());

        assertEquals(revocations.get(0).getRevocation().getNextUpdate(),
                simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(1, usedTimestamps.size());
        XmlTimestamp xmlTimestamp = usedTimestamps.get(0);

        assertEquals(xmlTimestamp.getSigningCertificate().getCertificate().getNotAfter(),
                simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void checkMinAndMaxUpdateValidTrustedCATest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_xades_level_lta_revo_freshness.xml"));
        assertNotNull(diagnosticData);

        List<XmlSignature> signatures = diagnosticData.getSignatures();
        assertEquals(1, signatures.size());
        XmlSignature xmlSignature = signatures.get(0);
        XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
        assertNotNull(signingCertificate);
        XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
        assertNotNull(caCertificate);

        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        caCertificate.getCertificate().setTrusted(xmlTrusted);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        CertificateConstraints caCertificateConstraints = signatureConstraints
                .getBasicSignatureConstraints().getCACertificate();
        caCertificateConstraints.getRevocationFreshness().setLevel(Level.FAIL);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(1, usedTimestamps.size());
        XmlTimestamp xmlTimestamp = usedTimestamps.get(0);
        XmlSigningCertificate signTstCertificate = xmlTimestamp.getSigningCertificate();
        assertNotNull(signTstCertificate);

        List<XmlCertificateRevocation> revocations = signTstCertificate.getCertificate().getRevocations();
        assertEquals(2, revocations.size());
        Date firstUpdateTime = null;
        for (XmlCertificateRevocation revocation : revocations) {
            if (firstUpdateTime == null || firstUpdateTime.after(revocation.getRevocation().getNextUpdate())) {
                firstUpdateTime = revocation.getRevocation().getNextUpdate();
            }
        }
        assertNotNull(firstUpdateTime);

        assertEquals(firstUpdateTime, simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));

        assertEquals(xmlTimestamp.getSigningCertificate().getCertificate().getNotAfter(),
                simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void checkMinAndMaxUpdateValidTrustedCAAndTstIssuerTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_xades_level_lta_revo_freshness.xml"));
        assertNotNull(diagnosticData);

        List<XmlSignature> signatures = diagnosticData.getSignatures();
        assertEquals(1, signatures.size());
        XmlSignature xmlSignature = signatures.get(0);
        XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
        assertNotNull(signingCertificate);
        XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
        assertNotNull(caCertificate);

        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        caCertificate.getCertificate().setTrusted(xmlTrusted);

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(1, usedTimestamps.size());
        XmlTimestamp xmlTimestamp = usedTimestamps.get(0);
        XmlSigningCertificate signTstCertificate = xmlTimestamp.getSigningCertificate();
        assertNotNull(signTstCertificate);

        xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        signTstCertificate.getCertificate().setTrusted(xmlTrusted);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();

        List<XmlCertificateRevocation> revocations = signingCertificate.getCertificate().getRevocations();
        assertEquals(2, revocations.size());
        Date firstUpdateTime = null;
        for (XmlCertificateRevocation revocation : revocations) {
            if (firstUpdateTime == null || firstUpdateTime.after(revocation.getRevocation().getNextUpdate())) {
                firstUpdateTime = revocation.getRevocation().getNextUpdate();
            }
        }
        assertNotNull(firstUpdateTime);

        assertEquals(firstUpdateTime, simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));

        assertEquals(xmlTimestamp.getSigningCertificate().getCertificate().getNotAfter(),
                simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void checkMinAndMaxNoTstTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_xades_level_lta_revo_freshness.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.setUsedTimestamps(Collections.emptyList());

        List<XmlSignature> signatures = diagnosticData.getSignatures();
        assertEquals(1, signatures.size());
        XmlSignature xmlSignature = signatures.get(0);

        xmlSignature.setFoundTimestamps(Collections.emptyList());

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
        assertNotNull(signingCertificate);
        XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
        assertNotNull(caCertificate);
        List<XmlCertificateRevocation> revocations = caCertificate.getCertificate().getRevocations();
        assertEquals(1, revocations.size());

        assertEquals(revocations.get(0).getRevocation().getNextUpdate(),
                simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));

        assertEquals(signingCertificate.getCertificate().getNotAfter(),
                simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void checkMinAndMaxUpdateValidAtSignTimeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_xades_level_lta_revo_freshness.xml"));
        assertNotNull(diagnosticData);

        List<XmlSignature> signatures = diagnosticData.getSignatures();
        assertEquals(1, signatures.size());
        XmlSignature xmlSignature = signatures.get(0);
        XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
        assertNotNull(signingCertificate);
        XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
        assertNotNull(caCertificate);

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(1, usedTimestamps.size());
        XmlTimestamp xmlTimestamp = usedTimestamps.get(0);
        xmlTimestamp.setProductionTime(xmlSignature.getClaimedSigningTime());

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();

        List<XmlCertificateRevocation> revocations = caCertificate.getCertificate().getRevocations();
        assertEquals(1, revocations.size());

        assertEquals(revocations.get(0).getRevocation().getNextUpdate(),
                simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));

        assertEquals(xmlTimestamp.getSigningCertificate().getCertificate().getNotAfter(),
                simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void checkMinAndMaxUpdateValidTrustedCATstAtSignTimeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_xades_level_lta_revo_freshness.xml"));
        assertNotNull(diagnosticData);

        List<XmlSignature> signatures = diagnosticData.getSignatures();
        assertEquals(1, signatures.size());
        XmlSignature xmlSignature = signatures.get(0);
        XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
        assertNotNull(signingCertificate);
        XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
        assertNotNull(caCertificate);

        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        caCertificate.getCertificate().setTrusted(xmlTrusted);

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(1, usedTimestamps.size());
        XmlTimestamp xmlTimestamp = usedTimestamps.get(0);
        xmlTimestamp.setProductionTime(xmlSignature.getClaimedSigningTime());

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();

        assertNull(simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));
        assertEquals(xmlTimestamp.getSigningCertificate().getCertificate().getNotAfter(),
                simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

        checkReports(reports);
    }

    @Test
    void revocationFreshnessSigningCertificateTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        CertificateConstraints signingCertificateConstraints = signatureConstraints
                .getBasicSignatureConstraints().getSigningCertificate();

        TimeConstraint constraint = new TimeConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setUnit(TimeUnit.SECONDS);
        constraint.setValue(0);
        signingCertificateConstraints.setRevocationFreshness(constraint);

        signatureConstraints.getBasicSignatureConstraints().getCACertificate()
                .getRevocationFreshness().setLevel(Level.IGNORE);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        XmlCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        String signingCertificateId = signingCertificate.getId();
        String caCertificateId = signingCertificate.getSigningCertificate().getCertificate().getId();

        boolean signingCertificateFound = false;
        boolean caCertificateFound = false;
        boolean rootCertificateFound = false;
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());
        for (XmlSubXCV subXCV : subXCVs) {
            if (signingCertificateId.equals(subXCV.getId())) {
                XmlRFC rfc = subXCV.getRFC();
                assertNotNull(rfc);
                assertEquals(Indication.INDETERMINATE, rfc.getConclusion().getIndication());
                assertEquals(SubIndication.TRY_LATER, rfc.getConclusion().getSubIndication());

                boolean revocationFreshnessCheckFound = false;
                for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
                    if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_RFC_IRIF_ANS.getId(), xmlConstraint.getError().getKey());
                        revocationFreshnessCheckFound = true;
                    }
                }
                assertTrue(revocationFreshnessCheckFound);

                signingCertificateFound = true;

            } else if (caCertificateId.equals(subXCV.getId())) {
                XmlRFC rfc = subXCV.getRFC();
                assertNotNull(rfc);
                assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

                boolean revocationFreshnessCheckFound = false;
                for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
                    if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                        revocationFreshnessCheckFound = true;
                    }
                }
                assertTrue(revocationFreshnessCheckFound);
                caCertificateFound = true;

            } else {
                XmlRFC rfc = subXCV.getRFC();
                assertNull(rfc);

                rootCertificateFound = true;
            }
        }
        assertTrue(signingCertificateFound);
        assertTrue(caCertificateFound);
        assertTrue(rootCertificateFound);

        checkReports(reports);
    }

    @Test
    void revocationFreshnessSigningCertificateWithTimeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        CertificateConstraints signingCertificateConstraints = signatureConstraints
                .getBasicSignatureConstraints().getSigningCertificate();

        TimeConstraint constraint = new TimeConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setUnit(TimeUnit.HOURS);
        constraint.setValue(24);
        signingCertificateConstraints.setRevocationFreshness(constraint);

        signatureConstraints.getBasicSignatureConstraints().getCACertificate()
                .getRevocationFreshness().setLevel(Level.IGNORE);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        XmlCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        String signingCertificateId = signingCertificate.getId();
        String caCertificateId = signingCertificate.getSigningCertificate().getCertificate().getId();

        boolean signingCertificateFound = false;
        boolean caCertificateFound = false;
        boolean rootCertificateFound = false;
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());
        for (XmlSubXCV subXCV : subXCVs) {
            if (signingCertificateId.equals(subXCV.getId())) {
                XmlRFC rfc = subXCV.getRFC();
                assertNotNull(rfc);
                assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

                boolean revocationFreshnessCheckFound = false;
                for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
                    if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        revocationFreshnessCheckFound = true;
                    }
                }
                assertTrue(revocationFreshnessCheckFound);

                signingCertificateFound = true;

            } else if (caCertificateId.equals(subXCV.getId())) {
                XmlRFC rfc = subXCV.getRFC();
                assertNotNull(rfc);
                assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

                boolean revocationFreshnessCheckFound = false;
                for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
                    if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                        revocationFreshnessCheckFound = true;
                    }
                }
                assertTrue(revocationFreshnessCheckFound);
                caCertificateFound = true;

            } else {
                XmlRFC rfc = subXCV.getRFC();
                assertNull(rfc);

                rootCertificateFound = true;
            }
        }
        assertTrue(signingCertificateFound);
        assertTrue(caCertificateFound);
        assertTrue(rootCertificateFound);

        checkReports(reports);
    }

    @Test
    void revocationFreshnessCACertificateTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate()
                .getRevocationFreshness().setLevel(Level.IGNORE);

        CertificateConstraints caCertificateConstraints = signatureConstraints
                .getBasicSignatureConstraints().getCACertificate();

        TimeConstraint constraint = new TimeConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setUnit(TimeUnit.SECONDS);
        constraint.setValue(0);
        caCertificateConstraints.setRevocationFreshness(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        XmlCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        String signingCertificateId = signingCertificate.getId();
        String caCertificateId = signingCertificate.getSigningCertificate().getCertificate().getId();

        boolean signingCertificateFound = false;
        boolean caCertificateFound = false;
        boolean rootCertificateFound = false;
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());
        for (XmlSubXCV subXCV : subXCVs) {
            if (signingCertificateId.equals(subXCV.getId())) {
                XmlRFC rfc = subXCV.getRFC();
                assertNotNull(rfc);
                assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

                boolean revocationFreshnessCheckFound = false;
                for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
                    if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                        revocationFreshnessCheckFound = true;
                    }
                }
                assertTrue(revocationFreshnessCheckFound);

                signingCertificateFound = true;

            } else if (caCertificateId.equals(subXCV.getId())) {
                XmlRFC rfc = subXCV.getRFC();
                assertNotNull(rfc);
                assertEquals(Indication.INDETERMINATE, rfc.getConclusion().getIndication());
                assertEquals(SubIndication.TRY_LATER, rfc.getConclusion().getSubIndication());

                boolean revocationFreshnessCheckFound = false;
                for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
                    if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_RFC_IRIF_ANS.getId(), xmlConstraint.getError().getKey());
                        revocationFreshnessCheckFound = true;
                    }
                }
                assertTrue(revocationFreshnessCheckFound);

                caCertificateFound = true;

            } else {
                XmlRFC rfc = subXCV.getRFC();
                assertNull(rfc);

                rootCertificateFound = true;
            }
        }
        assertTrue(signingCertificateFound);
        assertTrue(caCertificateFound);
        assertTrue(rootCertificateFound);

        checkReports(reports);
    }

    @Test
    void revocationFreshnessCACertificateNextUpdateCheckTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

        signatureConstraints.getBasicSignatureConstraints().getSigningCertificate()
                .getRevocationFreshness().setLevel(Level.IGNORE);

        CertificateConstraints caCertificateConstraints = signatureConstraints
                .getBasicSignatureConstraints().getCACertificate();
        caCertificateConstraints.setRevocationFreshness(null);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        caCertificateConstraints.setRevocationFreshnessNextUpdate(constraint);

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
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        XmlCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        String signingCertificateId = signingCertificate.getId();
        String caCertificateId = signingCertificate.getSigningCertificate().getCertificate().getId();

        boolean signingCertificateFound = false;
        boolean caCertificateFound = false;
        boolean rootCertificateFound = false;
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());
        for (XmlSubXCV subXCV : subXCVs) {
            if (signingCertificateId.equals(subXCV.getId())) {
                XmlRFC rfc = subXCV.getRFC();
                assertNotNull(rfc);
                assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

                boolean revocationFreshnessCheckFound = false;
                boolean revocationFreshnessNextUpdateCheckFound = false;
                for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
                    if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                        revocationFreshnessCheckFound = true;
                    } else if (MessageTag.BBB_RFC_IRIF_TUNU.getId().equals(xmlConstraint.getName().getKey())) {
                        revocationFreshnessNextUpdateCheckFound = true;
                    }
                }
                assertTrue(revocationFreshnessCheckFound);
                assertFalse(revocationFreshnessNextUpdateCheckFound);

                signingCertificateFound = true;

            } else if (caCertificateId.equals(subXCV.getId())) {
                XmlRFC rfc = subXCV.getRFC();
                assertNotNull(rfc);
                assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

                boolean revocationFreshnessCheckFound = false;
                boolean revocationFreshnessNextUpdateCheckFound = false;
                for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
                    if (MessageTag.BBB_RFC_IRIF_TUNU.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        revocationFreshnessNextUpdateCheckFound = true;
                    } else if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
                        revocationFreshnessCheckFound = true;
                    }
                }
                assertFalse(revocationFreshnessCheckFound);
                assertTrue(revocationFreshnessNextUpdateCheckFound);

                caCertificateFound = true;

            } else {
                XmlRFC rfc = subXCV.getRFC();
                assertNull(rfc);

                rootCertificateFound = true;
            }
        }
        assertTrue(signingCertificateFound);
        assertTrue(caCertificateFound);
        assertTrue(rootCertificateFound);

        checkReports(reports);
    }

}
