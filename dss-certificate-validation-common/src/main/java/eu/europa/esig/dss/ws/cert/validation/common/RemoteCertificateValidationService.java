package eu.europa.esig.dss.ws.cert.validation.common;

import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

public class RemoteCertificateValidationService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteCertificateValidationService.class);

	private CertificateVerifier verifier;

	public void setVerifier(CertificateVerifier verifier) {
		this.verifier = verifier;
	}
	
	public CertificateReportsDTO validateCertificate(RemoteCertificate certificate, List<RemoteCertificate> certificateChain, 
			Date validationTime) {
		LOG.info("ValidateCertificate in process...");
		CertificateValidator validator = initValidator(certificate, certificateChain, validationTime);
		
		CertificateReports reports = validator.validate();
		CertificateReportsDTO certificateReportsDTO = new CertificateReportsDTO(reports.getDiagnosticDataJaxb(), 
				reports.getSimpleReportJaxb(), reports.getDetailedReportJaxb());
		LOG.info("ValidateCertificate is finished");
		
		return certificateReportsDTO;
	}
	
	private CertificateValidator initValidator(RemoteCertificate certificate, List<RemoteCertificate> certificateChain, 
			Date validationTime) {
		if (Utils.isCollectionNotEmpty(certificateChain)) {
			CertificateSource adjunctCertSource = new CommonCertificateSource();
			for (RemoteCertificate certificateInChain : certificateChain) {
				CertificateToken certificateChainItem = RemoteCertificateConverter.toCertificateToken(certificateInChain);
				if (certificateChainItem != null) {
					adjunctCertSource.addCertificate(certificateChainItem);
				}
			}
			verifier.setAdjunctCertSource(adjunctCertSource);
		}
		
		CertificateToken certificateToken = RemoteCertificateConverter.toCertificateToken(certificate);
		CertificateValidator certificateValidator = CertificateValidator.fromCertificate(certificateToken);
		certificateValidator.setCertificateVerifier(verifier);
		if (validationTime != null) {
			certificateValidator.setValidationTime(validationTime);
		}
		
		return certificateValidator;
	}

}
