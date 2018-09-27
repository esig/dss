package eu.europa.esig.dss.validation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.RemoteConverter;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

public class RemoteDocumentValidationService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteDocumentValidationService.class);

	private CertificateVerifier verifier;

	public void setVerifier(CertificateVerifier verifier) {
		this.verifier = verifier;
	}

	public ReportsDTO validateDocument(RemoteDocument signedFile, RemoteDocument originalFile, RemoteDocument policy) {
		LOG.info("ValidateDocument in process...");
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

		ReportsDTO reportsDTO = new ReportsDTO(reports.getDiagnosticDataJaxb(), reports.getSimpleReportJaxb(), reports.getDetailedReportJaxb());
		LOG.info("ValidateDocument is finished");
		return reportsDTO;
	}

	public List<RemoteDocument> getOriginalDocuments(RemoteDocument signedFile, RemoteDocument originalFile, String signatureId) {
		LOG.info("GetOriginalDocuments in process...");
		DocumentValidator validator = initValidator(signedFile, originalFile);

		if (signatureId == null) {
			List<AdvancedSignature> signatures = validator.getSignatures();
			if (signatures.size() > 0) {
				LOG.debug("SignatureId is not defined, the first signature is used");
				signatureId = signatures.get(0).getId();
			}
		}

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signatureId);
		List<RemoteDocument> remoteDocuments = RemoteConverter.toRemoteDocuments(originalDocuments);
		LOG.info("GetOriginalDocuments is finished");
		return remoteDocuments;
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
