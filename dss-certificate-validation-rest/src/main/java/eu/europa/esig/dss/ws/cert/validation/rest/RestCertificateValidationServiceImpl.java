package eu.europa.esig.dss.ws.cert.validation.rest;

import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.cert.validation.rest.client.RestCertificateValidationService;

@SuppressWarnings("serial")
public class RestCertificateValidationServiceImpl implements RestCertificateValidationService {
	
	private RemoteCertificateValidationService validationService;
	
	public void setValidationService(RemoteCertificateValidationService validationService) {
		this.validationService = validationService;
	}

	@Override
	public CertificateReportsDTO validateCertificate(CertificateToValidateDTO certificateToValidate) {
		return validationService.validateCertificate(certificateToValidate.getCertificate(), certificateToValidate.getCertificateChain(), 
				certificateToValidate.getValidationTime());
	}

}
