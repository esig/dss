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
package eu.europa.esig.dss.validation.executor.DSS2049;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.EIDAS;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.validation.executor.AbstractTestValidationExecutor;
import eu.europa.esig.dss.validation.executor.certificate.DefaultCertificateProcessExecutor;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class DSS2049CertQualTest extends AbstractTestValidationExecutor {
	
	@Test
	public void test() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, true);
		CertificateReports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, CertificateQualification.QCERT_FOR_ESIG_QSCD, true, true);
	}
	
	@Test
	public void lotlFailWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(false, true);
		CertificateReports reports = execute(diagnosticData, Level.WARN);
		assertValid(reports, CertificateQualification.QCERT_FOR_ESIG_QSCD, true, true);
	}
	
	@Test
	public void lotlFailWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(false, true);
		CertificateReports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, CertificateQualification.NA, false, false);
	}
	
	@Test
	public void tlFailWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, false);
		CertificateReports reports = execute(diagnosticData, Level.WARN);
		assertValid(reports, CertificateQualification.QCERT_FOR_ESIG_QSCD, true, true);
	}
	
	@Test
	public void tlFailWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, false);
		CertificateReports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, CertificateQualification.NA, true, false);
	}
	
	private XmlDiagnosticData getDiagnosticData(boolean isLOTLWellSigned, boolean isTLWellSigned) throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2049/dss2049-cert-diag-data.xml"));
		assertNotNull(diagnosticData);
		
		List<XmlTrustedList> trustedLists = diagnosticData.getTrustedLists();
		assertEquals(2, trustedLists.size());
		XmlTrustedList xmlLOTL = trustedLists.get(0);
		xmlLOTL.setWellSigned(isLOTLWellSigned);
		XmlTrustedList xmlSigTL = trustedLists.get(1);
		xmlSigTL.setWellSigned(isTLWellSigned);
		
		return diagnosticData;
	}
	
	private CertificateReports execute(XmlDiagnosticData diagnosticData, Level tlWellSignedlLevel) throws Exception {
		DefaultCertificateProcessExecutor executor = new DefaultCertificateProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		
		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		EIDAS eidasConstraints = defaultPolicy.getEIDASConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(tlWellSignedlLevel);
		eidasConstraints.setTLWellSigned(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setCertificateId(diagnosticData.getUsedCertificates().get(0).getId());

		return executor.execute();
	}
	
	private void assertValid(CertificateReports reports, CertificateQualification certQualification, boolean assertLOTLValid, boolean assertTLValid) {
		SimpleCertificateReport simpleReport = reports.getSimpleReport();
		
		List<String> certificateIds = simpleReport.getCertificateIds();
		assertEquals(3, certificateIds.size());
		
		assertEquals(certQualification, simpleReport.getQualificationAtCertificateIssuance());
		assertEquals(certQualification, simpleReport.getQualificationAtValidationTime());
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		List<XmlCertificate> certificates = detailedReport.getCertificates();
		XmlCertificate xmlCertificate = certificates.get(0);
		
		List<XmlConstraint> constraints = xmlCertificate.getConstraint();
			
		int lotlsProcessed = 0;
		int tlsProcessed = 0;
		boolean isLOTLValid = false;
		boolean isTLValid = false;
		boolean acceptableFound = false;
		for (XmlConstraint constraint : constraints) {
			if (MessageTag.QUAL_LIST_OF_TRUSTED_LISTS_ACCEPT.name().equals(constraint.getName().getKey())) {
				++lotlsProcessed;
				if (XmlStatus.OK.equals(constraint.getStatus())) {
					isLOTLValid = true;
				}
			} else if (MessageTag.QUAL_TRUSTED_LIST_ACCEPT.name().equals(constraint.getName().getKey())) {
				++tlsProcessed;
				if (XmlStatus.OK.equals(constraint.getStatus())) {
					isTLValid = true;
				}
			} else if (MessageTag.QUAL_VALID_TRUSTED_LIST_PRESENT.name().equals(constraint.getName().getKey())) {
				if (XmlStatus.OK.equals(constraint.getStatus())) {
					acceptableFound = true;
				}
			}
		}
		assertEquals(1, lotlsProcessed);
		assertEquals(assertLOTLValid ? 1 : 0, tlsProcessed);
		assertEquals(assertLOTLValid, isLOTLValid);
		assertEquals(assertTLValid, isTLValid);
		assertEquals(assertLOTLValid && assertTLValid, acceptableFound);
		
	}

}
