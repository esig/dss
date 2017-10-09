package eu.europa.esig.dss.validation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

public class RemoteDocumentValidationService {

	private CertificateVerifier verifier;

	public void setVerifier(CertificateVerifier verifier) {
		this.verifier = verifier;
	}

	public ReportsDTO validateDocument(RemoteDocument signedFile, RemoteDocument originalFile, RemoteDocument policy) {

		DSSDocument signedDocument = new InMemoryDocument(signedFile.getBytes(), signedFile.getName(), signedFile.getMimeType());
		SignedDocumentValidator signedDocValidator = SignedDocumentValidator.fromDocument(signedDocument);
		signedDocValidator.setCertificateVerifier(verifier);

		if (originalFile != null && Utils.isArrayNotEmpty(originalFile.getBytes())) {
			List<DSSDocument> list = new ArrayList<DSSDocument>();
			DSSDocument orignalDocument = new InMemoryDocument(originalFile.getBytes(), originalFile.getName(), originalFile.getMimeType());
			list.add(orignalDocument);
			signedDocValidator.setDetachedContents(list);
		}

		Reports reports = null;
		if (policy == null) {
			reports = signedDocValidator.validateDocument();
		} else {
			try (ByteArrayInputStream bais = new ByteArrayInputStream(policy.getBytes())) {
				reports = signedDocValidator.validateDocument(bais);
			} catch (IOException e) {
				throw new DSSException(e);
			}
		}

		return new ReportsDTO(reports.getDiagnosticDataJaxb(), reports.getSimpleReportJaxb(), reports.getDetailedReportJaxb());
	}

}
