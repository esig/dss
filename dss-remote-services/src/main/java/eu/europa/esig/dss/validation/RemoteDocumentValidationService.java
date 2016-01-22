package eu.europa.esig.dss.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class RemoteDocumentValidationService {

	private CertificateVerifier verifier;
	
	public RemoteDocumentValidationService(CertificateVerifier verifier) {
		this.verifier = verifier;
	}
	
	public ReportsDTO validateDocument(RemoteDocument signedFile, RemoteDocument originalFile, ConstraintsParameters policy) {
		
		DSSDocument signedDocument = new InMemoryDocument(signedFile.getBytes()); 
		SignedDocumentValidator signedDocValidator = SignedDocumentValidator.fromDocument(signedDocument);
		signedDocValidator.setCertificateVerifier(verifier);
		
		if(originalFile != null && originalFile.getBytes().length > 0) {
			List<DSSDocument> list = new ArrayList<DSSDocument>();
			DSSDocument orignalDocument = new InMemoryDocument(originalFile.getBytes());
			list.add(orignalDocument);
			signedDocValidator.setDetachedContents(list);
		}
		
		Reports reports = policy != null ? signedDocValidator.validateDocument(policy) : signedDocValidator.validateDocument();
		
		ReportsDTO result = new ReportsDTO(reports.getDiagnosticData().getJaxbModel(), reports.getSimpleReport().getJaxbModel()
				, reports.getDetailedReport().getJAXBModel());
		
		return result;
	}
}
