package eu.europa.esig.dss;

import java.sql.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.dto.CertificateReportsDTO;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonCertificateSource;

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
