package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.validation.reports.dto.DataToValidateDTO;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

@SuppressWarnings("serial")
public class RestDocumentValidationServiceImpl implements RestDocumentValidationService {
	
	private RemoteDocumentValidationService validationService;
	
	public void setValidationService(RemoteDocumentValidationService validationService) {
		this.validationService = validationService;
	}
	
	@Override
	public ReportsDTO validateSignature(DataToValidateDTO dataToValidate) {
		return validationService.validateDocument(dataToValidate.getSignedDocument(), dataToValidate.getOriginalDocument(), dataToValidate.getPolicy());
	}

}
