package eu.europa.esig.dss.ws.cert.validation.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

public class RemoteCertificateValidationServiceTest {
	
	private RemoteCertificateValidationService validationService;
	
	@Before
	public void init() {
		validationService = new RemoteCertificateValidationService();
		validationService.setVerifier(new CommonCertificateVerifier());
	}
	
	@Test
	public void testWithCertificateChainAndValidationTime() {
		CertificateToValidateDTO certificateDTO = getCompleteCertificateToValidateDTO();
		
		CertificateReportsDTO reportsDTO = validationService.validateCertificate(certificateDTO.getCertificate(), 
				certificateDTO.getCertificateChain(), certificateDTO.getValidationTime());
		validateReports(reportsDTO);
		
		XmlDiagnosticData diagnosticData = reportsDTO.getDiagnosticData();
		assertTrue(certificateDTO.getValidationTime().compareTo(diagnosticData.getValidationDate()) == 0);
	}
	
	@Test
	public void noCertificateChainAndValidationTimeProvidedTest() {
		CertificateToValidateDTO certificateDTO = getCompleteCertificateToValidateDTO();
		CertificateReportsDTO reportsDTO = validationService.validateCertificate(certificateDTO.getCertificate(), null, null);
		validateReports(reportsDTO);
	}
	
	@Test(expected = NullPointerException.class)
	public void testWithNoCertificateProvided() {
		validationService.validateCertificate(null, null, null);
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
		return new CertificateToValidateDTO(remoteCertificate, Arrays.asList(issuerCertificate), validationDate);
	}
	
	protected void validateReports(CertificateReportsDTO reportsDTO) {
		assertNotNull(reportsDTO.getDiagnosticData());
		assertNotNull(reportsDTO.getSimpleCertificateReport());
		assertNotNull(reportsDTO.getDetailedReport());
		
		XmlDiagnosticData diagnosticData = reportsDTO.getDiagnosticData();
		List<XmlChainItem> chain = reportsDTO.getSimpleCertificateReport().getChain();
		assertEquals(3, chain.size());
		List<XmlCertificate> usedCertificates = diagnosticData.getUsedCertificates();
		for (XmlCertificate certificate : usedCertificates) {
			if (chain.get(0).getId().equals(certificate.getId())) {
				assertEquals(2, certificate.getCertificateChain().size());
			}
		}
		assertNotNull(diagnosticData.getValidationDate());
		
		CertificateReports certificateReports = new CertificateReports(reportsDTO.getDiagnosticData(), reportsDTO.getDetailedReport(), reportsDTO.getSimpleCertificateReport());
		assertNotNull(certificateReports);
	}

}
