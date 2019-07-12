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
package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.CertificateReports;

public class CertificateProcessExecutorTest extends AbstractValidationExecutorTest {

	@Test
	public void deRevoked() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/de_revoked.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-0E9B5C373AFEC1CED5723FCD9231F793BB330FFBF2B94BB8698301C90405B9BF";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		XmlDetailedReport detailedReportJaxb = reports.getDetailedReportJaxb();
		assertNotNull(detailedReportJaxb);
		assertNotNull(detailedReportJaxb.getCertificate());
		assertEquals(2, detailedReportJaxb.getTLAnalysis().size());
		assertEquals(1, detailedReportJaxb.getBasicBuildingBlocks().size());
		assertEquals(0, detailedReportJaxb.getSignatures().size());

		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		List<String> certificateIds = simpleReport.getCertificateIds();
		assertEquals(2, certificateIds.size());
		for (String certId : certificateIds) {
			assertNotNull(simpleReport.getCertificateNotAfter(certId));
			assertNotNull(simpleReport.getCertificateNotBefore(certId));
		}
		assertNotNull(simpleReport.getQualificationAtCertificateIssuance());
		assertNotNull(simpleReport.getQualificationAtValidationTime());
		assertNotNull(simpleReport.getValidationTime());
		assertNotNull(simpleReport.getJaxbModel());
		assertEquals(Indication.INDETERMINATE, simpleReport.getCertificateIndication(certificateId));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getCertificateSubIndication(certificateId));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getCertificateCrlUrls(certificateId)));
		assertNotNull(simpleReport.getCertificateRevocationDate(certificateId));
		assertEquals(RevocationReason.UNSPECIFIED, simpleReport.getCertificateRevocationReason(certificateId));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getCertificateCrlUrls(certificateId)));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getTrustAnchorVATNumbers()));

		XmlSimpleCertificateReport simpleReportJaxb = reports.getSimpleReportJaxb();
		assertNotNull(simpleReportJaxb);
		assertNotNull(simpleReportJaxb.getChain());
		assertEquals(2, simpleReportJaxb.getChain().size());

		XmlChainItem cert = simpleReportJaxb.getChain().get(0);
		assertEquals(certificateId, cert.getId());
		assertNotNull(cert.getQualificationAtIssuance());
		assertNotNull(cert.getQualificationAtValidation());
		assertNull(cert.getTrustAnchors());

		XmlChainItem ca = simpleReportJaxb.getChain().get(1);
		assertNull(ca.getQualificationAtIssuance());
		assertNull(ca.getQualificationAtValidation());
		assertNotNull(ca.getTrustAnchors());

	}

	@Test
	public void beTSA() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/be_tsa.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-D74AF393CF3B506DA33B46BC52B49CD6FAC12B2BDAA9CE1FBA25C0C1E4EBBE19";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		XmlDetailedReport detailedReportJaxb = reports.getDetailedReportJaxb();
		assertNotNull(detailedReportJaxb);
		assertNotNull(detailedReportJaxb.getCertificate());
		assertEquals(2, detailedReportJaxb.getTLAnalysis().size());
		assertEquals(1, detailedReportJaxb.getBasicBuildingBlocks().size());
		assertEquals(0, detailedReportJaxb.getSignatures().size());

		XmlSimpleCertificateReport simpleReportJaxb = reports.getSimpleReportJaxb();
		assertNotNull(simpleReportJaxb);
		assertNotNull(simpleReportJaxb.getChain());
		assertEquals(2, simpleReportJaxb.getChain().size());

		XmlChainItem cert = simpleReportJaxb.getChain().get(0);
		assertEquals(certificateId, cert.getId());
		assertNotNull(cert.getQualificationAtIssuance());
		assertNotNull(cert.getQualificationAtValidation());
		assertNull(cert.getTrustAnchors());

		XmlChainItem ca = simpleReportJaxb.getChain().get(1);
		assertNull(ca.getQualificationAtIssuance());
		assertNull(ca.getQualificationAtValidation());
		assertNotNull(ca.getTrustAnchors());

	}

	@Test
	public void dkNoChain() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/dk_no_chain.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-3ECBC4648AA3BCB671976F53D7516F774DB1C886FAB81FE5469462181187DB8D";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		XmlDetailedReport detailedReportJaxb = reports.getDetailedReportJaxb();
		assertNotNull(detailedReportJaxb);
		assertNotNull(detailedReportJaxb.getCertificate());
		assertEquals(0, detailedReportJaxb.getTLAnalysis().size());
		assertEquals(1, detailedReportJaxb.getBasicBuildingBlocks().size());
		assertEquals(0, detailedReportJaxb.getSignatures().size());

		XmlSimpleCertificateReport simpleReportJaxb = reports.getSimpleReportJaxb();
		assertNotNull(simpleReportJaxb);
		assertNotNull(simpleReportJaxb.getChain());
		assertEquals(1, simpleReportJaxb.getChain().size());

		XmlChainItem cert = simpleReportJaxb.getChain().get(0);
		assertEquals(certificateId, cert.getId());
		assertNotNull(cert.getQualificationAtIssuance());
		assertNotNull(cert.getQualificationAtValidation());
		assertNull(cert.getTrustAnchors());

	}

	@Test
	public void inconsistentTrustService() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/inconsistent-state.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-A1E2D4CA9C521332369FA3224F0B7282AD2596E8A7416CBC0DF087E05D8F5502";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.CERT_FOR_ESIG, simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.CERT_FOR_ESIG, simpleReport.getQualificationAtValidationTime());
	}

	@Test
	public void invalidTL() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/invalid-tl.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-86CA5DDDDCB6CA73C77511DFF3C94961BD675CA15111810103942CA7D96DCE1B";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.CERT_FOR_ESIG, simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.CERT_FOR_ESIG, simpleReport.getQualificationAtValidationTime());
	}

	@Test
	public void expiredTL() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/expired-tl.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-86CA5DDDDCB6CA73C77511DFF3C94961BD675CA15111810103942CA7D96DCE1B";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.QCERT_FOR_ESIG_QSCD,
				simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.QCERT_FOR_ESIG_QSCD, simpleReport.getQualificationAtValidationTime());
	}

	@Test
	public void wsaQC() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/cert_WSAQC.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-24A830ADC0D077255FD14A607513D398CDB278A53A3DBAB79AC4ADE6A66EEAA6";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.QCERT_FOR_WSA, simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.QCERT_FOR_WSA, simpleReport.getQualificationAtValidationTime());
	}

	@Test
	public void overruleNotQualified() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/overrule-NotQualified-tl.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-86CA5DDDDCB6CA73C77511DFF3C94961BD675CA15111810103942CA7D96DCE1B";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.CERT_FOR_ESIG, simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.CERT_FOR_ESIG, simpleReport.getQualificationAtValidationTime());
	}

	@Test
	public void overruleNoQSCD() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/overrule-NoQSCD-tl.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-86CA5DDDDCB6CA73C77511DFF3C94961BD675CA15111810103942CA7D96DCE1B";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();
		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.QCERT_FOR_ESIG, simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.QCERT_FOR_ESIG, simpleReport.getQualificationAtValidationTime());
	}

	@Test
	public void overruleQSCD() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/overrule-QSCD-tl.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-86CA5DDDDCB6CA73C77511DFF3C94961BD675CA15111810103942CA7D96DCE1B";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();
		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.QCERT_FOR_ESIG_QSCD,
				simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.QCERT_FOR_ESIG_QSCD, simpleReport.getQualificationAtValidationTime());
	}

	@Test
	public void overruleQualified() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/overrule-Qualified-tl.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-86CA5DDDDCB6CA73C77511DFF3C94961BD675CA15111810103942CA7D96DCE1B";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();
		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.QCERT_FOR_ESIG_QSCD,
				simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.QCERT_FOR_ESIG_QSCD, simpleReport.getQualificationAtValidationTime());
	}

	@Test
	public void multipleSDI() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/multiple-sdi.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-C011F11E98AEFF48798AD5874A7A7F0C8192ADD1AB6D37825FE42C2F9F5847EB";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();
		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.QCERT_FOR_ESIG,
				simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.QCERT_FOR_ESIG, simpleReport.getQualificationAtValidationTime());
	}

	@Test
	public void withdrawn() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/withdrawn.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-18D60FFCE5904ED1E2B3DE04A7BA48BF7F904A34D6988962B964843649A33456";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();
		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.CERT_FOR_ESIG, simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.CERT_FOR_ESIG, simpleReport.getQualificationAtValidationTime());
	}

	@Test
	public void twoSDIdiffentResults() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/2-sdi-different-results.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-E4A94773CF7B28C2BDF25015BE6716E501E73AB82BF0A9788D0DF8AD14D6876D";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		XmlDetailedReport detailedReportJaxb = reports.getDetailedReportJaxb();
		XmlCertificate certificate = detailedReportJaxb.getCertificate();
		List<XmlValidationCertificateQualification> validationCertificateQualification = certificate.getValidationCertificateQualification();
		for (XmlValidationCertificateQualification xmlValidationCertificateQualification : validationCertificateQualification) {
			assertEquals(Indication.FAILED, xmlValidationCertificateQualification.getConclusion().getIndication());
		}
	}

	@Test
	public void trustAnchor() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-validation/trust-anchor.xml"));
		assertNotNull(diagnosticData);

		String certificateId = "C-702DD5C1A093CF0A9D71FADD9BF9A7C5857D89FB73B716E867228B3C2BEB968F";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();
		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertEquals(CertificateQualification.NA, simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(CertificateQualification.NA, simpleReport.getQualificationAtValidationTime());
	}
	
}
