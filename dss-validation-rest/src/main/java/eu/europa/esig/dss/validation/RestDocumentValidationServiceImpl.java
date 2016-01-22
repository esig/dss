package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class RestDocumentValidationServiceImpl implements RestDocumentValidationService {
	
	private RemoteDocumentValidationService validationService;
	
	public RestDocumentValidationServiceImpl(RemoteDocumentValidationService validationService) {
		this.validationService = validationService;
	}
	
	@Override
	public ReportsDTO validateSignature(RemoteDocument signedFile, RemoteDocument originalFile,
			ConstraintsParameters policy) {
		return validationService.validateDocument(signedFile, originalFile, policy);
	}

}
