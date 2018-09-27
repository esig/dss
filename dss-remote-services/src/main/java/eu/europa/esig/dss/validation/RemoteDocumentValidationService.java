package eu.europa.esig.dss.validation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.RemoteConverter;
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

		DocumentValidator validator = initValidator(signedFile, originalFile);

		Reports reports = null;
		if (policy == null) {
			reports = validator.validateDocument();
		} else {
			try (ByteArrayInputStream bais = new ByteArrayInputStream(policy.getBytes())) {
				reports = validator.validateDocument(bais);
			} catch (IOException e) {
				throw new DSSException(e);
			}
		}

		return new ReportsDTO(reports.getDiagnosticDataJaxb(), reports.getSimpleReportJaxb(), reports.getDetailedReportJaxb());
	}

	public List<RemoteDocument> getOriginalDocuments(RemoteDocument signedFile, RemoteDocument originalFile, String signatureId) {
		DocumentValidator validator = initValidator(signedFile, originalFile);

		if (signatureId == null) {
			List<AdvancedSignature> signatures = validator.getSignatures();
			if (signatures.size() > 0) {
				signatureId = signatures.get(0).getId();
			}
		}

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signatureId);
		return RemoteConverter.toRemoteDocuments(originalDocuments);
	}

	private DocumentValidator initValidator(RemoteDocument signedFile, RemoteDocument originalFile) {
		DSSDocument signedDocument = RemoteConverter.toDSSDocument(signedFile);
		SignedDocumentValidator signedDocValidator = SignedDocumentValidator.fromDocument(signedDocument);
		signedDocValidator.setCertificateVerifier(verifier);
		if (originalFile != null && Utils.isArrayNotEmpty(originalFile.getBytes())) {
			signedDocValidator.setDetachedContents(Arrays.asList(RemoteConverter.toDSSDocument(originalFile)));
		}
		return signedDocValidator;
	}

}
