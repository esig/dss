package eu.europa.esig.dss.validation;

import java.util.List;

import eu.europa.esig.dss.DataToValidateDTO;
import eu.europa.esig.dss.RemoteDocument;
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

	@Override
	public List<RemoteDocument> getOriginalDocuments(DataToValidateDTO dataToValidate) {
		return validationService.getOriginalDocuments(dataToValidate.getSignedDocument(), dataToValidate.getOriginalDocument(),
				dataToValidate.getSignatureId());
	}
}
