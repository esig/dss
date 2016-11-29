package eu.europa.esig.dss.asic.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

public class ASiCContainerWithXAdESValidator extends AbstractASiCContainerValidator {

	private ASiCContainerWithXAdESValidator() {
		super(null);
	}

	public ASiCContainerWithXAdESValidator(final DSSDocument asicContainer) {
		super(asicContainer);
		analyseEntries();
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return ASiCUtils.isASiCContainer(dssDocument) && ASiCUtils.isArchiveContainsCorrectSignatureExtension(dssDocument, ".xml");
	}

	@Override
	boolean isAcceptedSignature(String entryName) {
		return ASiCUtils.isXAdES(entryName);
	}

	@Override
	boolean isAcceptedManifest(String entryName) {
		return ASiCUtils.isASiCManifestWithXAdES(entryName);
	}

	@Override
	List<DocumentValidator> getValidators() {
		List<DocumentValidator> validators = new ArrayList<DocumentValidator>();
		for (final DSSDocument signature : getSignatureDocuments()) {
			XMLDocumentValidator xadesValidator = new XMLDocumentValidator(signature);
			xadesValidator.setCertificateVerifier(certificateVerifier);
			xadesValidator.setProcessExecutor(processExecutor);
			xadesValidator.setPolicyFile(policyDocument);
			xadesValidator.setDetachedContents(getSignedDocuments());
			validators.add(xadesValidator);
		}
		return validators;
	}

}
