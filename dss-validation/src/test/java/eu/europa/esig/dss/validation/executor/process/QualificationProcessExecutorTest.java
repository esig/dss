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
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcCompliance;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustServiceProvider;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QualificationProcessExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void qualification() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/preEIDAS.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.INDETERMINATE_ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
    }

    @Test
    void qualificationQESig() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/qualifQESig.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
    }

    @Test
    void qualificationQESigInvalidTstExtKeyUsage() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/qualifNA-invalid-tst.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
    }

    @Test
    void qualificationQESigBrexit() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/qualifQESigBrexit.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        assertNotNull(etsiValidationReport);
        SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
        assertNotNull(signatureValidationReport);
        assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()),
                SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void qualificationNA() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/qualifNA.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.NA, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        assertNotNull(etsiValidationReport);
        SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
        assertNotNull(signatureValidationReport);
        assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()),
                SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void webSiteAuth() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_WSA.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.NOT_ADES, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        assertNotNull(etsiValidationReport);
        SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
        assertNotNull(signatureValidationReport);
        assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()),
                SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void doubleAsieAndQCType() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_double_ASIE_qctype.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        // see test case 5.1.5
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.UNKNOWN_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void doubleAsie() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_double_ASIE.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.ADESEAL_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        assertNotNull(etsiValidationReport);
        SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
        assertNotNull(signatureValidationReport);
        assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()),
                SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void asicSXades() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/asic-s-xades-diag-data.xml"));
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
    void commisign() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/commisign.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.UNKNOWN, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        // no qualifiers

        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        assertNotNull(etsiValidationReport);
        SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
        assertNotNull(signatureValidationReport);
        assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()),
                SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

        checkReports(reports);
    }

    @Test
    void grantedTspTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-tsp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();

        boolean certTypeCheckProcessed = false;
        for (XmlConstraint constraint : validationSignQual.getConstraint()) {
            if (MessageTag.QUAL_CERT_TYPE_AT_ST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                certTypeCheckProcessed = true;
            }
        }
        assertTrue(certTypeCheckProcessed);
    }

    @Test
    void grantedTspWithQualifierTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-tsp-with-qualifier.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignQual);

        assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
        for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
            boolean consistencyCheckProcessed = false;
            for (XmlConstraint constraint : certQualification.getConstraint()) {
                if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    consistencyCheckProcessed = true;
                }
            }
            assertTrue(consistencyCheckProcessed);
        }
    }

    @Test
    void grantedTspWithUnknownQualifierTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-tsp-with-unknown-qualifier.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3C)));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignQual);

        assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
        for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
            boolean consistencyCheckProcessed = false;
            for (XmlConstraint constraint : certQualification.getConstraint()) {
                if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3C.getId(), constraint.getWarning().getKey());
                    consistencyCheckProcessed = true;
                }
            }
            assertTrue(consistencyCheckProcessed);
        }
    }

    @Test
    void grantedTspQscdOverruleTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-tsp-qscd-overrule.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignQual);

        assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
        for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
            boolean consistencyCheckProcessed = false;
            boolean qscdConsistencyCheckProcessed = false;
            for (XmlConstraint constraint : certQualification.getConstraint()) {
                if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    consistencyCheckProcessed = true;
                } else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    qscdConsistencyCheckProcessed = true;
                }
            }
            assertTrue(consistencyCheckProcessed);
            assertTrue(qscdConsistencyCheckProcessed);
        }
    }

    @Test
    void grantedTspSscdOverruleTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-tsp-sscd-overrule.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_CERTIFICATE_ISSUANCE_TIME)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_BEST_SIGNATURE_TIME)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3B)));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignQual);

        assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
        for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
            boolean consistencyCheckProcessed = false;
            boolean qscdConsistencyCheckProcessed = false;
            for (XmlConstraint constraint : certQualification.getConstraint()) {
                if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3B.getId(), constraint.getWarning().getKey());
                    consistencyCheckProcessed = true;
                } else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS.getId(), constraint.getError().getKey());
                    qscdConsistencyCheckProcessed = true;
                }
            }
            assertTrue(consistencyCheckProcessed);
            assertTrue(qscdConsistencyCheckProcessed);
        }
    }

    @Test
    void grantedTspSscdAndQscdOverruleTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-tsp-sscd-and-qscd-overrule.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignQual);

        assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
        for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
            boolean consistencyCheckProcessed = false;
            boolean qscdConsistencyCheckProcessed = false;
            for (XmlConstraint constraint : certQualification.getConstraint()) {
                if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    consistencyCheckProcessed = true;
                } else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    qscdConsistencyCheckProcessed = true;
                }
            }
            assertTrue(consistencyCheckProcessed);
            assertTrue(qscdConsistencyCheckProcessed);
        }
    }

    @Test
    void qscdWithNoSscdOverruleTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/qscd-with-no-sscd-overrule.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_BEST_SIGNATURE_TIME)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3B)));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignQual);

        assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
        for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
            boolean consistencyCheckProcessed = false;
            boolean qscdConsistencyCheckProcessed = false;
            for (XmlConstraint constraint : certQualification.getConstraint()) {
                if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3B.getId(), constraint.getWarning().getKey());
                    consistencyCheckProcessed = true;
                } else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS.getId(), constraint.getError().getKey());
                    qscdConsistencyCheckProcessed = true;
                }
            }
            assertTrue(consistencyCheckProcessed);
            assertTrue(qscdConsistencyCheckProcessed);
        }
    }

    @Test
    void qscdWithQscdOverruleConflictTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-tsp-qscd-overrule-conflict.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_BEST_SIGNATURE_TIME)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3)));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignQual);

        assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
        for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
            boolean consistencyCheckProcessed = false;
            boolean qscdConsistencyCheckProcessed = false;
            for (XmlConstraint constraint : certQualification.getConstraint()) {
                if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3.getId(), constraint.getWarning().getKey());
                    consistencyCheckProcessed = true;
                } else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS.getId(), constraint.getError().getKey());
                    qscdConsistencyCheckProcessed = true;
                }
            }
            assertTrue(consistencyCheckProcessed);
            assertTrue(qscdConsistencyCheckProcessed);
        }
    }

    @Test
    void qscdWithManagedOnBehalfAndQscdOverruleConflictTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-tsp-managedonbehalf-and-qscd-overrule-conflict.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignQual);

        assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
        for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
            boolean consistencyCheckProcessed = false;
            boolean qscdConsistencyCheckProcessed = false;
            for (XmlConstraint constraint : certQualification.getConstraint()) {
                if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    consistencyCheckProcessed = true;
                } else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    qscdConsistencyCheckProcessed = true;
                }
            }
            assertTrue(consistencyCheckProcessed);
            assertTrue(qscdConsistencyCheckProcessed);
        }
    }


    @Test
    void qscdWithManagedOnBehalfAndNoQscdOverruleConflictTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-tsp-managedonbehalf-and-noqscd-overrule-conflict.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_BEST_SIGNATURE_TIME)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3)));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignQual);

        assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
        for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
            boolean consistencyCheckProcessed = false;
            boolean qscdConsistencyCheckProcessed = false;
            for (XmlConstraint constraint : certQualification.getConstraint()) {
                if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3.getId(), constraint.getWarning().getKey());
                    consistencyCheckProcessed = true;
                } else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS.getId(), constraint.getError().getKey());
                    qscdConsistencyCheckProcessed = true;
                }
            }
            assertTrue(consistencyCheckProcessed);
            assertTrue(qscdConsistencyCheckProcessed);
        }
    }


    @Test
    void qscdWithStatusAsInCertAndQscdOverruleConflictTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-tsp-statusasincert-and-qscd-overrule-conflict.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)));
        assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_BEST_SIGNATURE_TIME)));
        assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3A)));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignQual);

        assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
        for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
            boolean consistencyCheckProcessed = false;
            boolean qscdConsistencyCheckProcessed = false;
            for (XmlConstraint constraint : certQualification.getConstraint()) {
                if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3A.getId(), constraint.getWarning().getKey());
                    consistencyCheckProcessed = true;
                } else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                    assertEquals(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS.getId(), constraint.getError().getKey());
                    qscdConsistencyCheckProcessed = true;
                }
            }
            assertTrue(consistencyCheckProcessed);
            assertTrue(qscdConsistencyCheckProcessed);
        }
    }

    @Test
    void withdrawnAtTOIAndGrantedAtTOSTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/withdrawn-at-toi-granted-at-tos.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

    @Test
    void grantedAtTOIAndWithdrawnAtTOSTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/granted-at-toi-withdrawn-at-tos.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

    @Test
    void esigAtTOIAndEsealAtTOSTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/esig-at-toi-eseal-at-tos.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.UNKNOWN_QC_QSCD, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();

        boolean certTypeCheckProcessed = false;
        for (XmlConstraint constraint : validationSignQual.getConstraint()) {
            if (MessageTag.QUAL_CERT_TYPE_AT_ST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.QUAL_CERT_TYPE_AT_ST_ANS.getId(), constraint.getWarning().getKey());
                certTypeCheckProcessed = true;
            }
        }
        assertTrue(certTypeCheckProcessed);
    }

    @Test
    void noQscdAtTOIAndQscdAtTOSTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/noqscd-at-toi-qscd-at-tos.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

    @Test
    void qscdAtTOIAndNoQscdAtTOSTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/sig-qualification/qscd-at-toi-noqscd-at-tos.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

    @Test
    void getCertQualificationTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/DSS-1330-diag-data.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        DetailedReport detailedReport = reports.getDetailedReport();

        assertEquals(CertificateQualification.NA, detailedReport.getCertificateQualificationAtIssuance("certId"));
        assertEquals(CertificateQualification.NA, detailedReport.getCertificateQualificationAtValidation("certId"));
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> detailedReport.getCertificateXCVConclusion("certId"));
        assertEquals("Only supported in report for certificate", exception.getMessage());
    }

    @Test
    void qcWithConflictInTypesTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/sig-qualification/post-eidas-qc-types-conflict.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.UNKNOWN_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

    @Test
    void noQCWithConflictInTypesTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/sig-qualification/post-eidas-no-qc-types-conflict.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.UNKNOWN, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

    @Test
    void noQcComplianceForESigTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/sig-qualification/post-eidas-no-qc-compliance-for-esig.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        // for eSig only when type or QcStatement is defined
        assertEquals(SignatureQualification.UNKNOWN_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

    @Test
    void qcComplianceForESigTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/sig-qualification/post-eidas-no-qc-compliance-for-esig.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate signingCertificate = xmlSignature.getSigningCertificate().getCertificate();

        XmlQcStatements qcStatements = null;
        for (XmlCertificateExtension certificateExtension : signingCertificate.getCertificateExtensions()) {
            if (CertificateExtensionEnum.QC_STATEMENTS.getOid().equals(certificateExtension.getOID())) {
                qcStatements = (XmlQcStatements) certificateExtension;
            }
        }
        if (qcStatements == null) {
            qcStatements = new XmlQcStatements();
            qcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
            signingCertificate.getCertificateExtensions().add(qcStatements);

        }

        XmlQcCompliance qcCompliance = new XmlQcCompliance();
        qcCompliance.setPresent(true);
        qcStatements.setQcCompliance(qcCompliance);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        // QcStatement is default for eSig
        assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

    @Test
    void noQcComplianceForESigWithQSCDTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/sig-qualification/post-eidas-no-qc-compliance-for-esig-sscd.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        // for eSig only when type or QcStatement is defined
        assertEquals(SignatureQualification.UNKNOWN_QC_QSCD, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

    @Test
    void qcComplianceForESigWithQSCDTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/sig-qualification/post-eidas-no-qc-compliance-for-esig-sscd.xml"));
        assertNotNull(diagnosticData);

        XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
        XmlCertificate signingCertificate = xmlSignature.getSigningCertificate().getCertificate();

        XmlQcStatements qcStatements = null;
        for (XmlCertificateExtension certificateExtension : signingCertificate.getCertificateExtensions()) {
            if (CertificateExtensionEnum.QC_STATEMENTS.getOid().equals(certificateExtension.getOID())) {
                qcStatements = (XmlQcStatements) certificateExtension;
            }
        }
        if (qcStatements == null) {
            qcStatements = new XmlQcStatements();
            qcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
            signingCertificate.getCertificateExtensions().add(qcStatements);

        }

        XmlQcCompliance qcCompliance = new XmlQcCompliance();
        qcCompliance.setPresent(true);
        qcStatements.setQcCompliance(qcCompliance);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        // for eSig only when type or QcStatement is defined
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        List<XmlTrustServiceProvider> trustServices = signingCertificate.getTrustServiceProviders();
        String tlId = trustServices.get(0).getTL().getId();

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
        assertNotNull(tlAnalysis);

        // Ensure no MRA is enacted
        boolean mraFound = false;
        for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
            if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
                mraFound = true;
                break;
            }
        }
        assertFalse(mraFound);

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature signature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationSignatureQualification validationSignatureQualification = signature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.QESIG, validationSignatureQualification.getSignatureQualification());

        assertEquals(Indication.PASSED, validationSignatureQualification.getConclusion().getIndication());
        assertFalse(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
                i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));
        assertFalse(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.QUAL_HAS_METS_ANS)));

        List<XmlValidationCertificateQualification> validationCertificateQualification = validationSignatureQualification.getValidationCertificateQualification();
        assertEquals(2, validationCertificateQualification.size());

        for (XmlValidationCertificateQualification certificateQualification : validationCertificateQualification) {
            boolean mraTrustServiceCheckFound = false;
            for (XmlConstraint constraint : certificateQualification.getConstraint()) {
                if (MessageTag.QUAL_HAS_METS.getId().equals(constraint.getName().getKey())) {
                    mraTrustServiceCheckFound = true;
                    break;
                }
            }
            assertFalse(mraTrustServiceCheckFound);
        }
    }

    @Test
    void inconsistentTlByTypeWithQCAndQSCDTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/sig-qualification/inconsistent-tl-by-type.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(SignatureQualification.UNKNOWN_QC_QSCD, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

}
