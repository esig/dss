package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.RemoteCertificateValidationService;
import eu.europa.esig.dss.dto.CertificateReportsDTO;
import eu.europa.esig.dss.dto.CertificateToValidateDTO;

@SuppressWarnings("serial")
public class RestCertificateValidationServiceImpl implements RestCertificateValidationService {
	
	public RemoteCertificateValidationService validationService;
	
	public void setValidationService(RemoteCertificateValidationService validationService) {
		this.validationService = validationService;
	}

	@Override
	public CertificateReportsDTO validateCertificate(CertificateToValidateDTO certificateToValidate) {
		return validationService.validateCertificate(certificateToValidate.getCertificate(), certificateToValidate.getCertificateChain(), 
				certificateToValidate.getValidationTime());
	}

}
