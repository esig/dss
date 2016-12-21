package eu.europa.esig.dss.asic.validation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestFile;

/**
 * This class is an implementation to validate ASiC containers with CAdES signature(s)
 * 
 */
public class ASiCContainerWithCAdESValidator extends AbstractASiCContainerValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCContainerWithCAdESValidator.class);

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
	AbstractASiCContainerExtractor getArchiveExtractor() {
		return new ASiCWithCAdESContainerExtractor(document);
	}

	@Override
	List<DocumentValidator> getValidators() {
		if (validators == null) {
			validators = new ArrayList<DocumentValidator>();
			for (final DSSDocument signature : getSignatureDocuments()) {
				CMSDocumentForASiCValidator cadesValidator = new CMSDocumentForASiCValidator(signature);
				cadesValidator.setCertificateVerifier(certificateVerifier);
				cadesValidator.setProcessExecutor(processExecutor);
				cadesValidator.setSignaturePolicyProvider(signaturePolicyProvider);
				cadesValidator.setValidationCertPool(validationCertPool);
				cadesValidator.setDetachedContents(getSignedDocuments(signature));
				validators.add(cadesValidator);
			}
		}
		return validators;
	}

	private List<DSSDocument> getSignedDocuments(DSSDocument signature) {
		ASiCContainerType type = getContainerType();
		if (ASiCContainerType.ASiC_S == type) {
			return getSignedDocuments(); // Collection size should be equals 1
		} else if (ASiCContainerType.ASiC_E == type) {
			// the manifest file is signed
			// we need first to check the manifest file and its digests
			ASiCEWithCAdESManifestValidator manifestValidator = new ASiCEWithCAdESManifestValidator(signature, getManifestDocuments(), getSignedDocuments());
			DSSDocument linkedManifest = manifestValidator.getLinkedManifest();
			if (linkedManifest != null) {
				return Arrays.asList(linkedManifest);
			} else {
				return Collections.emptyList();
			}
		} else {
			LOG.warn("Unknown asic container type (returns all signed documents)");
			return getSignedDocuments();
		}
	}

	@Override
	protected List<ManifestFile> getManifestFilesDecriptions() {
		List<ManifestFile> descriptions = new ArrayList<ManifestFile>();
		List<DSSDocument> manifestDocuments = getManifestDocuments();
		for (DSSDocument manifestDocument : manifestDocuments) {
			ASiCEWithCAdESManifestParser parser = new ASiCEWithCAdESManifestParser(manifestDocument);
			descriptions.add(parser.getDescription());
		}

		return descriptions;
	}

}
