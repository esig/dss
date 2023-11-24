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
package eu.europa.esig.dss.ws.cert.validation.common;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.Unmarshaller;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RemoteCertificateValidationServiceTest {
	
	private RemoteCertificateValidationService validationService;
	
	@BeforeEach
	public void init() {
		validationService = new RemoteCertificateValidationService();
		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		verifier.setAIASource(new DefaultAIASource(new IgnoreDataLoader()));
		validationService.setVerifier(verifier);
	}
	
	@Test
	public void testWithCertificateChainAndValidationTime() {
		CertificateToValidateDTO certificateDTO = getCompleteCertificateToValidateDTO();
		
		CertificateReportsDTO reportsDTO = validationService.validateCertificate(certificateDTO);
		validateReports(reportsDTO);
		
		XmlDiagnosticData diagnosticData = reportsDTO.getDiagnosticData();
		assertEquals(0, certificateDTO.getValidationTime().compareTo(diagnosticData.getValidationDate()));

		XmlSimpleCertificateReport simpleCertificateReport = reportsDTO.getSimpleCertificateReport();
		assertEquals("Certificate policy TL based", simpleCertificateReport.getValidationPolicy().getPolicyName());
	}
	
	@Test
	public void noCertificateChainAndValidationTimeProvidedTest() {
		CertificateToValidateDTO certificateDTO = getCompleteCertificateToValidateDTO();
		certificateDTO.setCertificateChain(null);
		CertificateReportsDTO reportsDTO = validationService.validateCertificate(certificateDTO);
		validateReports(reportsDTO);
	}
	
	@Test
	public void noCertificateChainNoStrategyAndValidationTimeProvidedTest() {
		CertificateToValidateDTO certificateDTO = getCompleteCertificateToValidateDTO();
		certificateDTO.setCertificateChain(null);
		certificateDTO.setTokenExtractionStrategy(null);
		CertificateReportsDTO reportsDTO = validationService.validateCertificate(certificateDTO);
		validateReports(reportsDTO);
	}

	@Test
	public void testWithValidationPolicy() {
		CertificateToValidateDTO certificateDTO = getCompleteCertificateToValidateDTO();

		RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));
		certificateDTO.setPolicy(policy);

		CertificateReportsDTO reportsDTO = validationService.validateCertificate(certificateDTO);
		validateReports(reportsDTO);

		XmlSimpleCertificateReport simpleCertificateReport = reportsDTO.getSimpleCertificateReport();
		assertEquals("QES AdESQC TL based (Test WebServices)", simpleCertificateReport.getValidationPolicy().getPolicyName());
	}

	@Test
	public void testWithDefaultValidationPolicy() throws Exception {
		CertificateToValidateDTO certificateDTO = getCompleteCertificateToValidateDTO();

		Unmarshaller unmarshaller = ValidationPolicyFacade.newFacade().getUnmarshaller(true);
		JAXBElement<ConstraintsParameters> unmarshal = (JAXBElement<ConstraintsParameters>) unmarshaller
				.unmarshal(ValidationPolicyFacade.class.getResourceAsStream("/constraint.xml"));

		ConstraintsParameters constraints = unmarshal.getValue();
		constraints.setName("Default Policy");

		RemoteCertificateValidationService validationService = new RemoteCertificateValidationService();
		validationService.setVerifier(new CommonCertificateVerifier());
		validationService.setDefaultValidationPolicy(new EtsiValidationPolicy(constraints));

		CertificateReportsDTO reportsDTO = validationService.validateCertificate(certificateDTO);
		validateReports(reportsDTO);

		XmlSimpleCertificateReport simpleCertificateReport = reportsDTO.getSimpleCertificateReport();
		assertEquals("Default Policy", simpleCertificateReport.getValidationPolicy().getPolicyName());
	}

	@Test
	public void testWithDefaultAndOverwrittenValidationPolicy() throws Exception {
		CertificateToValidateDTO certificateDTO = getCompleteCertificateToValidateDTO();

		RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));
		certificateDTO.setPolicy(policy);

		Unmarshaller unmarshaller = ValidationPolicyFacade.newFacade().getUnmarshaller(true);
		JAXBElement<ConstraintsParameters> unmarshal = (JAXBElement<ConstraintsParameters>) unmarshaller
				.unmarshal(ValidationPolicyFacade.class.getResourceAsStream("/constraint.xml"));

		ConstraintsParameters constraints = unmarshal.getValue();
		constraints.setName("Default Policy");

		RemoteCertificateValidationService validationService = new RemoteCertificateValidationService();
		validationService.setVerifier(new CommonCertificateVerifier());
		validationService.setDefaultValidationPolicy(new EtsiValidationPolicy(constraints));

		CertificateReportsDTO reportsDTO = validationService.validateCertificate(certificateDTO);
		validateReports(reportsDTO);

		XmlSimpleCertificateReport simpleCertificateReport = reportsDTO.getSimpleCertificateReport();
		assertEquals("QES AdESQC TL based (Test WebServices)", simpleCertificateReport.getValidationPolicy().getPolicyName());
	}

	@Test
	public void testWithNoCertificateProvided() {
		assertThrows(NullPointerException.class, () -> validationService.validateCertificate(null));
		CertificateToValidateDTO emptyDTO=	new CertificateToValidateDTO();
		assertThrows(NullPointerException.class, () -> validationService.validateCertificate(emptyDTO));
	}
	
	protected CertificateToValidateDTO getCompleteCertificateToValidateDTO() {
		RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
				DSSUtils.loadCertificate(new File("src/test/resources/good-user.cer")));
		RemoteCertificate issuerCertificate = RemoteCertificateConverter.toRemoteCertificate(
				DSSUtils.loadCertificate(new File("src/test/resources/good-ca.cer")));
		Calendar calendar = Calendar.getInstance();
		calendar.set(2018, 12, 31);
		Date validationDate = calendar.getTime();
		validationDate.setTime((validationDate.getTime() / 1000) * 1000); // clean millis
		return new CertificateToValidateDTO(remoteCertificate, Arrays.asList(issuerCertificate), validationDate,
				TokenExtractionStrategy.EXTRACT_CERTIFICATES_AND_REVOCATION_DATA);
	}
	
	protected void validateReports(CertificateReportsDTO reportsDTO) {
		assertNotNull(reportsDTO.getDiagnosticData());
		assertNotNull(reportsDTO.getSimpleCertificateReport());
		assertNotNull(reportsDTO.getDetailedReport());
		
		XmlDiagnosticData diagnosticData = reportsDTO.getDiagnosticData();
		List<XmlChainItem> chain = reportsDTO.getSimpleCertificateReport().getChain();
		assertNotNull(chain);
		assertTrue(chain.size() > 0);
		List<XmlCertificate> usedCertificates = diagnosticData.getUsedCertificates();
		assertNotNull(usedCertificates);
		assertTrue(usedCertificates.size() > 0);
		assertNotNull(diagnosticData.getValidationDate());
		
		CertificateReports certificateReports = new CertificateReports(reportsDTO.getDiagnosticData(), reportsDTO.getDetailedReport(), reportsDTO.getSimpleCertificateReport());
		assertNotNull(certificateReports);
	}

}
