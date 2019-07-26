package eu.europa.esig.dss.ws.cert.validation.soap;

import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.cert.validation.soap.client.SoapCertificateValidationService;
import eu.europa.esig.dss.ws.cert.validation.soap.client.WSCertificateReportsDTO;

@SuppressWarnings("serial")
public class SoapCertificateValidationServiceImpl implements SoapCertificateValidationService {
	
	private RemoteCertificateValidationService validationService;
	
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
