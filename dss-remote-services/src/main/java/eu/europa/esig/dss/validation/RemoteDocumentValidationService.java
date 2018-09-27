package eu.europa.esig.dss.validation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestDocument;
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

		DSSDocument signedDocument = getDSSDocument(signedFile);
		SignedDocumentValidator signedDocValidator = SignedDocumentValidator.fromDocument(signedDocument);
		signedDocValidator.setCertificateVerifier(verifier);

		if (originalFile != null && Utils.isArrayNotEmpty(originalFile.getBytes())) {
			signedDocValidator.setDetachedContents(Arrays.asList(getDSSDocument(originalFile)));
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

	public List<DSSDocument> getOriginalDocuments(RemoteDocument signedFile, String signatureId) {
		List<DSSDocument> originalDocuments = null;

		DSSDocument signedDocument = getDSSDocument(signedFile);
		SignedDocumentValidator signedDocValidator = SignedDocumentValidator.fromDocument(signedDocument);
		signedDocValidator.setCertificateVerifier(verifier);

		if (signatureId == null) {
			List<AdvancedSignature> signatures = null;
			try {
				signatures = signedDocValidator.getSignatures();
			} catch (Exception e) {
				throw new DSSException(e);
			}
			if (signatures.size() > 0) {
				signatureId = signatures.get(0).getId();
			}
		}

		if (signatureId != null) {
			originalDocuments = signedDocValidator.getOriginalDocuments(signatureId);
		}

		return originalDocuments;
	}

	private DSSDocument getDSSDocument(RemoteDocument remoteDocument) {
		if (remoteDocument.getDigestAlgorithm() != null) {
			DigestDocument digestDocument = new DigestDocument();
			digestDocument.addDigest(remoteDocument.getDigestAlgorithm(), Utils.toBase64(remoteDocument.getBytes()));
			digestDocument.setName(remoteDocument.getName());
			digestDocument.setMimeType(remoteDocument.getMimeType());
			return digestDocument;
		} else {
			return new InMemoryDocument(remoteDocument.getBytes(), remoteDocument.getName(), remoteDocument.getMimeType());
		}
	}

}
