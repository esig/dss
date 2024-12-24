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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualificationAtTime;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MRAEquivalenceContext;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MRAProcessExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void mraQeSigTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/mra/diag-data-mra-qesig.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        assertEquals(0, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertEquals(0, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
        String tlId = trustServices.get(0).getTrustedList().getId();

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
        assertNotNull(tlAnalysis);

        boolean mraFound = false;
        for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
            if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.QUAL_TL_IMRA_ANS.getId(), constraint.getInfo().getKey());
                mraFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(mraFound);

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.QESIG, validationSignatureQualification.getSignatureQualification());

        assertEquals(Indication.PASSED, validationSignatureQualification.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

        checkReports(reports);
    }

    @Test
    void noMraAdeSigTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/mra/diag-data-no-mra-adesig.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertEquals(0, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
        String tlId = trustServices.get(0).getTrustedList().getId();

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
        assertNotNull(tlAnalysis);

        boolean mraFound = false;
        for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
            if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.QUAL_TL_IMRA_ANS.getId(), constraint.getInfo().getKey());
                mraFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(mraFound);

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.ADESIG, validationSignatureQualification.getSignatureQualification());

        assertEquals(Indication.FAILED, validationSignatureQualification.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.QUAL_HAS_METS_ANS)));

        List<XmlValidationCertificateQualification> validationCertificateQualification = validationSignatureQualification.getValidationCertificateQualification();
        assertEquals(2, validationCertificateQualification.size());

        for (XmlValidationCertificateQualification certificateQualification : validationCertificateQualification) {
            boolean mraTrustServiceCheckFound = false;
            for (XmlConstraint constraint : certificateQualification.getConstraint()) {
                if (MessageTag.QUAL_HAS_METS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_HAS_METS_ANS.getId(), constraint.getError().getKey());
                    mraTrustServiceCheckFound = true;
                } else {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                }
            }
            assertTrue(mraTrustServiceCheckFound);
        }

        checkReports(reports);
    }

    @Test
    void mraAfterCertIssuanceTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/mra/diag-data-mra-qesig.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate xmlSigningCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        XmlTrustService trustService = xmlSigningCertificate.getTrustServiceProviders().get(0).getTrustServices().get(0);
        trustService.getMRATrustServiceMapping().setEquivalenceStatusStartingTime(new Date());

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertEquals(0, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
        String tlId = trustServices.get(0).getTrustedList().getId();

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
        assertNotNull(tlAnalysis);

        boolean mraFound = false;
        for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
            if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.QUAL_TL_IMRA_ANS.getId(), constraint.getInfo().getKey());
                mraFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(mraFound);

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.ADESIG, validationSignatureQualification.getSignatureQualification());

        assertEquals(Indication.FAILED, validationSignatureQualification.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.QUAL_HAS_METS_ANS)));

        List<XmlValidationCertificateQualification> validationCertificateQualification = validationSignatureQualification.getValidationCertificateQualification();
        assertEquals(2, validationCertificateQualification.size());

        for (XmlValidationCertificateQualification certificateQualification : validationCertificateQualification) {
            boolean mraTrustServiceCheckFound = false;
            for (XmlConstraint constraint : certificateQualification.getConstraint()) {
                if (MessageTag.QUAL_HAS_METS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_HAS_METS_ANS.getId(), constraint.getError().getKey());
                    mraTrustServiceCheckFound = true;
                } else {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                }
            }
            assertTrue(mraTrustServiceCheckFound);
        }

        checkReports(reports);
    }

    @Test
    void mraWithQTstsTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/mra/diag-data-mra-with-qtsts.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.ADESEAL, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertEquals(2, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(2, signatureTimestamps.size());
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : signatureTimestamps) {
            assertEquals(Indication.PASSED, timestamp.getIndication());
            assertEquals(TimestampQualification.QTSA, timestamp.getTimestampLevel().getValue());

            assertEquals(0, Utils.collectionSize(timestamp.getQualificationDetails().getError()));
            assertEquals(0, Utils.collectionSize(timestamp.getQualificationDetails().getWarning()));
            assertEquals(1, Utils.collectionSize(timestamp.getQualificationDetails().getInfo()));
            assertTrue(checkMessageValuePresence(convertMessages(timestamp.getQualificationDetails().getInfo()),
                    i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));
        }

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
        String tlId = trustServices.get(0).getTrustedList().getId();

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
        assertNotNull(tlAnalysis);

        boolean mraFound = false;
        for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
            if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.QUAL_TL_IMRA_ANS.getId(), constraint.getInfo().getKey());
                mraFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(mraFound);

        assertEquals(2, detailedReport.getTimestampIds().size());
        for (String tstId : detailedReport.getTimestampIds()) {
            assertEquals(TimestampQualification.QTSA, detailedReport.getTimestampQualification(tstId));
            eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(tstId);
            XmlValidationTimestampQualification validationTimestampQualification = xmlTimestamp.getValidationTimestampQualification();
            assertNotNull(validationTimestampQualification);

            List<XmlValidationTimestampQualificationAtTime> timestampQualificationsAtTime = validationTimestampQualification.getValidationTimestampQualificationAtTime();
            assertEquals(2, timestampQualificationsAtTime.size());

            for (XmlValidationTimestampQualificationAtTime timestampQualificationAtTime : timestampQualificationsAtTime) {
                boolean mraTrustServiceCheckFound = false;
                for (XmlConstraint constraint : timestampQualificationAtTime.getConstraint()) {
                    if (MessageTag.QUAL_HAS_METS.getId().equals(constraint.getName().getKey())) {
                        mraTrustServiceCheckFound = true;
                    }
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                }
                assertTrue(mraTrustServiceCheckFound);
            }
        }

        checkReports(reports);
    }

    @Test
    void mraWithTstsTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/mra/diag-data-mra-with-tsts.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.ADESEAL, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertEquals(2, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(2, signatureTimestamps.size());
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : signatureTimestamps) {
            assertEquals(Indication.PASSED, timestamp.getIndication());
            assertEquals(TimestampQualification.TSA, timestamp.getTimestampLevel().getValue());

            assertEquals(1, Utils.collectionSize(timestamp.getQualificationDetails().getError()));
            assertEquals(0, Utils.collectionSize(timestamp.getQualificationDetails().getWarning()));
            assertEquals(1, Utils.collectionSize(timestamp.getQualificationDetails().getInfo()));
            assertTrue(checkMessageValuePresence(convertMessages(timestamp.getQualificationDetails().getError()),
                    i18nProvider.getMessage(MessageTag.QUAL_HAS_METS_ANS)));
            assertTrue(checkMessageValuePresence(convertMessages(timestamp.getQualificationDetails().getInfo()),
                    i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));
        }

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
        String tlId = trustServices.get(0).getTrustedList().getId();

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
        assertNotNull(tlAnalysis);

        boolean mraFound = false;
        for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
            if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.QUAL_TL_IMRA_ANS.getId(), constraint.getInfo().getKey());
                mraFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(mraFound);

        assertEquals(2, detailedReport.getTimestampIds().size());
        for (String tstId : detailedReport.getTimestampIds()) {
            assertEquals(TimestampQualification.TSA, detailedReport.getTimestampQualification(tstId));
            eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(tstId);
            XmlValidationTimestampQualification validationTimestampQualification = xmlTimestamp.getValidationTimestampQualification();
            assertNotNull(validationTimestampQualification);

            List<XmlValidationTimestampQualificationAtTime> timestampQualificationsAtTime = validationTimestampQualification.getValidationTimestampQualificationAtTime();
            assertEquals(2, timestampQualificationsAtTime.size());

            for (XmlValidationTimestampQualificationAtTime timestampQualificationAtTime : timestampQualificationsAtTime) {
                boolean mraTrustServiceCheckFound = false;
                for (XmlConstraint constraint : timestampQualificationAtTime.getConstraint()) {
                    if (MessageTag.QUAL_HAS_METS.getId().equals(constraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                        assertEquals(MessageTag.QUAL_HAS_METS_ANS.getId(), constraint.getError().getKey());
                        mraTrustServiceCheckFound = true;
                    } else {
                        assertEquals(XmlStatus.OK, constraint.getStatus());
                    }
                }
                assertTrue(mraTrustServiceCheckFound);
            }
        }

        checkReports(reports);
    }

    @Test
    void mraQeSigArt14Test() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/mra/diag-data-mra-qesig.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTrustedList xmlTrustedList = xmlDiagnosticData.getTrustedLists().get(1);
        xmlTrustedList.setTSLType("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        assertEquals(0, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertEquals(0, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS_V1)));

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
        String tlId = trustServices.get(0).getTrustedList().getId();

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
        assertNotNull(tlAnalysis);

        boolean mraFound = false;
        for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
            if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.QUAL_TL_IMRA_ANS_V1.getId(), constraint.getInfo().getKey());
                mraFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(mraFound);

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.QESIG, validationSignatureQualification.getSignatureQualification());

        assertEquals(Indication.PASSED, validationSignatureQualification.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS_V1)));

        checkReports(reports);
    }

    @Test
    void mraQeSigArt27Test() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/mra/diag-data-mra-qesig.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTrustedList xmlTrustedList = xmlDiagnosticData.getTrustedLists().get(1);
        xmlTrustedList.setTSLType("http://ec.europa.eu/tools/lotl/mra/ades-lotl-tsl-type");

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        assertEquals(0, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertEquals(0, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS_V2)));

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
        String tlId = trustServices.get(0).getTrustedList().getId();

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
        assertNotNull(tlAnalysis);

        boolean mraFound = false;
        for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
            if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
                assertEquals(MessageTag.QUAL_TL_IMRA_ANS_V2.getId(), constraint.getInfo().getKey());
                mraFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(mraFound);

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.QESIG, validationSignatureQualification.getSignatureQualification());

        assertEquals(Indication.PASSED, validationSignatureQualification.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS_V2)));

        checkReports(reports);
    }

    @Test
    void mraCertEquivalenceRuleNotAppliedTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/mra/diag-data-mra-qesig-cert-rule-not-applied.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        assertEquals(0, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_HAS_METS_HCCECBA_ANS_2, MRAEquivalenceContext.QC_COMPLIANCE.getUri())));
        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
                simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();

        for (XmlValidationCertificateQualification certificateQualification : validationSignatureQualification.getValidationCertificateQualification()) {
            assertEquals(CertificateQualification.QCERT_FOR_ESIG_QSCD, certificateQualification.getCertificateQualification());

            boolean mraCertContentEquivalenceCheckFound = false;
            for (XmlConstraint constraint : certificateQualification.getConstraint()) {
                if (MessageTag.QUAL_HAS_METS_HCCECBA.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_HAS_METS_HCCECBA_ANS_2.getId(), constraint.getWarning().getKey());
                    mraCertContentEquivalenceCheckFound = true;
                } else {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                }
            }
            assertTrue(mraCertContentEquivalenceCheckFound);
        }

        checkReports(reports);
    }

}
