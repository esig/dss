package eu.europa.esig.dss.asic.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUnsupportedOperationException;
import eu.europa.esig.dss.asic.ASiCExtractResult;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.Reports;

public abstract class AbstractASiCContainerValidator extends SignedDocumentValidator {

	private ASiCExtractResult extractResult;

	private ASiCContainerType containerType;

	/**
	 * Default constructor used with reflexion (see SignedDocumentValidator)
	 */
	private AbstractASiCContainerValidator() {
		super(null);
		this.document = null;
	}

	protected AbstractASiCContainerValidator(final DSSDocument document) {
		super(null);
		this.document = document;
	}

	protected void analyseEntries() {
		AbstractASiCContainerExtractor extractor = getArchiveExtractor();
		extractResult = extractor.extract();

		containerType = ASiCUtils.getContainerType(document, extractResult.getMimeTypeDocument(), extractResult.getZipComment());
	}

	abstract AbstractASiCContainerExtractor getArchiveExtractor();

	public ASiCContainerType getContainerType() {
		return containerType;
	}

	@Override
	public List<AdvancedSignature> getSignatures() {

		ensureCertificatePoolInitialized();

		List<AdvancedSignature> allSignatures = new ArrayList<AdvancedSignature>();
		List<DocumentValidator> validators = getValidators();
		for (DocumentValidator documentValidator : validators) {
			allSignatures.addAll(documentValidator.getSignatures());
		}
		return allSignatures;
	}

	abstract List<DocumentValidator> getValidators();

	@Override
	public Reports validateDocument(final ValidationPolicy validationPolicy) {

		ensureCertificatePoolInitialized();

		Reports first = null;
		Reports previous = null;

		List<DocumentValidator> validators = getValidators();
		for (DocumentValidator validator : validators) {
			Reports currentReport = validator.validateDocument(validationPolicy);
			if (first == null) {
				first = currentReport;
			} else {
				previous.setNextReport(currentReport);
			}
			previous = currentReport;
		}

		return first;
	}

	protected List<DSSDocument> getSignatureDocuments() {
		return extractResult.getSignatureDocuments();
	}

	protected List<DSSDocument> getSignedDocuments() {
		return extractResult.getSignedDocuments();
	}

	protected List<DSSDocument> getManifestDocuments() {
		return extractResult.getManifestDocuments();
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) throws DSSException {
		// TODO
		throw new DSSUnsupportedOperationException("This method is not applicable for this kind of file!");
	}

}
