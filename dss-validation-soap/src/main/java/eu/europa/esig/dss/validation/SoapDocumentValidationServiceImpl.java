package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.DataToValidateDTO;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

@SuppressWarnings("serial")
public class SoapDocumentValidationServiceImpl implements SoapDocumentValidationService {

	private RemoteDocumentValidationService validationService;

	public void setValidationService(RemoteDocumentValidationService validationService) {
		this.validationService = validationService;
	}

	@Override
	public WSReportsDTO validateSignature(DataToValidateDTO dataToValidate) {
		ReportsDTO reportsDTO = validationService.validateDocument(dataToValidate.getSignedDocument(), dataToValidate.getOriginalDocument(),
				dataToValidate.getPolicy());
		return new WSReportsDTO(reportsDTO.getDiagnosticData(), reportsDTO.getSimpleReport(), reportsDTO.getDetailedReport());
	}
}
