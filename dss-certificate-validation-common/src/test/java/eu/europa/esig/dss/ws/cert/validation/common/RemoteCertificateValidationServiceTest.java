package eu.europa.esig.dss.ws.cert.validation.common;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

public class RemoteCertificateValidationServiceTest {
	
	private RemoteCertificateValidationService validationService;
	
	@BeforeEach
	public void init() {
		validationService = new RemoteCertificateValidationService();
		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		verifier.setDataLoader(new IgnoreDataLoader());
		validationService.setVerifier(verifier);
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
	
	@Test
	public void testWithNoCertificateProvided() {
		assertThrows(NullPointerException.class, () -> validationService.validateCertificate(null, null, null));
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
