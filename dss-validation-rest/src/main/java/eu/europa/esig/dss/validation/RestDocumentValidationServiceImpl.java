package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.dto.ValidationResultDTO;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class RestDocumentValidationServiceImpl implements RestDocumentValidationService {
	
	public RestDocumentValidationServiceImpl() {
	}
	
	@Override
	public ValidationResultDTO validateSignature(RemoteDocument signedFile, RemoteDocument originalFile,
			ConstraintsParameters policy) {
		DSSDocument signedDocument = new InMemoryDocument(signedFile.getBytes()); 
		SignedDocumentValidator signedDocValidator = SignedDocumentValidator.fromDocument(signedDocument);
		
		Reports reports = signedDocValidator.validateDocument(policy);
		
		ValidationResultDTO result = new ValidationResultDTO(reports.getDiagnosticData().getJaxbModel(), reports.getSimpleReport().getJaxbModel()
				, reports.getDetailedReport().getJAXBModel());
		return result;
	}

}
