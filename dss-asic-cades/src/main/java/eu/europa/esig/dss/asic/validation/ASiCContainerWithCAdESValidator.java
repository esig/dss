package eu.europa.esig.dss.asic.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.validation.DocumentValidator;

public class ASiCContainerWithCAdESValidator extends AbstractASiCContainerValidator {

	private ASiCContainerWithCAdESValidator() {
		super(null);
	}

	public ASiCContainerWithCAdESValidator(final DSSDocument asicContainer) {
		super(asicContainer);
		analyseEntries();
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return ASiCUtils.isASiCContainer(dssDocument) && ASiCUtils.isArchiveContainsCorrectSignatureExtension(dssDocument, ".p7s");
	}

	@Override
	boolean isAcceptedSignature(String entryName) {
		return ASiCUtils.isCAdES(entryName);
	}

	@Override
	boolean isAcceptedManifest(String entryName) {
		return ASiCUtils.isASiCManifestWithCAdES(entryName);
	}

	@Override
	List<DocumentValidator> getValidators() {
		List<DocumentValidator> validators = new ArrayList<DocumentValidator>();
		for (final DSSDocument signature : getSignatureDocuments()) {
			CMSDocumentValidator cadesValidator = new CMSDocumentValidator(signature);
			cadesValidator.setCertificateVerifier(certificateVerifier);
			cadesValidator.setProcessExecutor(processExecutor);
			cadesValidator.setDetachedContents(getOtherDocuments());
			validators.add(cadesValidator);
		}
		return validators;
	}

}
