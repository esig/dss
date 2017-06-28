package eu.europa.esig.dss.validation;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.esig.dss.validation.reports.dto.DataToValidateDTO;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

@SuppressWarnings("serial")
@WebService(serviceName = "DocumentValidationService", targetNamespace = "http://validation.dss.esig.europa.eu/", portName = "soap")
public class SoapDocumentValidationServiceImpl implements SoapDocumentValidationService {

	private RemoteDocumentValidationService validationService;

	public void setValidationService(RemoteDocumentValidationService validationService) {
		this.validationService = validationService;
	}

	@Override
	@WebResult(name = "WSReportsDTO")
	public WSReportsDTO validateSignature(@WebParam(name = "dataToValidateDTO") DataToValidateDTO dataToValidate) {
		ReportsDTO reportsDTO = validationService.validateDocument(dataToValidate.getSignedDocument(), dataToValidate.getOriginalDocument(),
				dataToValidate.getPolicy());
		return new WSReportsDTO(reportsDTO.getDiagnosticData(), reportsDTO.getSimpleReport(), reportsDTO.getDetailedReport());
	}
}
