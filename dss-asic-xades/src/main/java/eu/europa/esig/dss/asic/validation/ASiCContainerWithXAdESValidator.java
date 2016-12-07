package eu.europa.esig.dss.asic.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.validation.DocumentValidator;

/**
 * This class is an implemention to validate ASiC containers with XAdES signature(s)
 * 
 */
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
	AbstractASiCContainerExtractor getArchiveExtractor() {
		return new ASiCWithXAdESContainerExtractor(document);
	}

	@Override
	List<DocumentValidator> getValidators() {
		if (validators == null) {
			validators = new ArrayList<DocumentValidator>();
			for (final DSSDocument signature : getSignatureDocuments()) {
				XMLDocumentForASiCValidator xadesValidator = new XMLDocumentForASiCValidator(signature);
				xadesValidator.setCertificateVerifier(certificateVerifier);
				xadesValidator.setProcessExecutor(processExecutor);
				xadesValidator.setValidationCertPool(validationCertPool);
				xadesValidator.setSignaturePolicyProvider(signaturePolicyProvider);
				xadesValidator.setDetachedContents(getSignedDocuments());
				validators.add(xadesValidator);
			}
		}
		return validators;
	}

}
