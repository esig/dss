package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.RemoteCertificateValidationService;
import eu.europa.esig.dss.dto.CertificateReportsDTO;
import eu.europa.esig.dss.dto.CertificateToValidateDTO;

@SuppressWarnings("serial")
public class SoapCertificateValidationServiceImpl implements SoapCertificateValidationService {
	
	public RemoteCertificateValidationService validationService;
	
	public void setValidationService(RemoteCertificateValidationService validationService) {
		this.validationService = validationService;
	}

	@Override
	public WSCertificateReportsDTO validateCertificate(CertificateToValidateDTO certificateToValidate) {
		 CertificateReportsDTO reports = validationService.validateCertificate(certificateToValidate.getCertificate(), certificateToValidate.getCertificateChain(), 
				certificateToValidate.getValidationTime());
		 return new WSCertificateReportsDTO(reports.getDiagnosticData(), reports.getSimpleCertificateReport(), reports.getDetailedReport());
	}

}
