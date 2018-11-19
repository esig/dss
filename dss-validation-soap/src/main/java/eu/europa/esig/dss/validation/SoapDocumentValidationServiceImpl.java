package eu.europa.esig.dss.validation;

import java.util.List;

import eu.europa.esig.dss.DataToValidateDTO;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

@SuppressWarnings("serial")
public class SoapDocumentValidationServiceImpl implements SoapDocumentValidationService {

	private RemoteDocumentValidationService validationService;

	public void setValidationService(RemoteDocumentValidationService validationService) {
		this.validationService = validationService;
	}

	@Override
	public WSReportsDTO validateSignature(DataToValidateDTO dataToValidate) {
		ReportsDTO reportsDTO = validationService.validateDocument(dataToValidate.getSignedDocument(), dataToValidate.getOriginalDocuments(),
				dataToValidate.getPolicy());
		return new WSReportsDTO(reportsDTO.getDiagnosticData(), reportsDTO.getSimpleReport(), reportsDTO.getDetailedReport());
	}

	@Override
	public List<RemoteDocument> getOriginalDocuments(DataToValidateDTO dataToValidate) {
		return validationService.getOriginalDocuments(dataToValidate.getSignedDocument(), dataToValidate.getOriginalDocuments(),
				dataToValidate.getSignatureId());
	}

}
