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
import eu.europa.esig.dss.cades.validation.CMSTimestampValidator;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.TimestampReference;
import eu.europa.esig.dss.validation.TimestampReferenceCategory;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.TimestampValidator;
import eu.europa.esig.dss.x509.TimestampType;

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

	@Override
	protected void attachExternalTimestamps(List<AdvancedSignature> allSignatures) {
		ASiCContainerType type = getContainerType();
		if (ASiCContainerType.ASiC_E == type) {
			List<TimestampValidator> currentTimestampValidators = getTimestampValidators();
			if (!currentTimestampValidators.isEmpty()) {
				for (TimestampValidator tspValidator : currentTimestampValidators) {
					TimestampToken timestamp = tspValidator.getTimestamp();
					if (timestamp.isSignatureValid()) {
						for (AdvancedSignature advancedSignature : allSignatures) {

							List<TimestampReference> timestampedReferences = new ArrayList<TimestampReference>();
							timestampedReferences.addAll(advancedSignature.getTimestampedReferences());

							List<TimestampToken> coveredTsps = new ArrayList<TimestampToken>();
							coveredTsps.addAll(advancedSignature.getContentTimestamps());
							coveredTsps.addAll(advancedSignature.getSignatureTimestamps());
							for (final TimestampToken coveredTsp : coveredTsps) {
								timestampedReferences.add(new TimestampReference(coveredTsp.getDSSIdAsString(), TimestampReferenceCategory.TIMESTAMP));
							}
							timestamp.setTimestampedReferences(timestampedReferences);

							advancedSignature.addExternalTimestamp(timestamp);
						}
					}
				}
			}
		}
	}

	private List<TimestampValidator> getTimestampValidators() {
		List<TimestampValidator> timestampValidators = new ArrayList<TimestampValidator>();
		for (final DSSDocument timestamp : getTimestampDocuments()) {
			TimestampValidator timestampValidator = new CMSTimestampValidator(timestamp, TimestampType.ARCHIVE_TIMESTAMP);
			timestampValidator.setCertificateVerifier(certificateVerifier);
			timestampValidator.setTimestampedData(getTimestampedArchiveManifest(timestamp));
			timestampValidators.add(timestampValidator);
		}
		return timestampValidators;
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

	private DSSDocument getTimestampedArchiveManifest(DSSDocument timestamp) {
		List<DSSDocument> signedDocs = new ArrayList<DSSDocument>();
		signedDocs.addAll(getSignedDocuments());
		signedDocs.addAll(getManifestDocuments());
		signedDocs.addAll(getSignatureDocuments());

		ASiCEWithCAdESManifestValidator manifestValidator = new ASiCEWithCAdESManifestValidator(timestamp, getArchiveManifestDocuments(), signedDocs);
		return manifestValidator.getLinkedManifest();
	}

	@Override
	protected List<ManifestFile> getManifestFilesDecriptions() {
		List<ManifestFile> descriptions = new ArrayList<ManifestFile>();
		List<DSSDocument> manifestDocuments = getManifestDocuments();
		for (DSSDocument manifestDocument : manifestDocuments) {
			ASiCEWithCAdESManifestParser parser = new ASiCEWithCAdESManifestParser(manifestDocument);
			descriptions.add(parser.getDescription());
		}

		List<DSSDocument> archiveManifestDocuments = getArchiveManifestDocuments();
		for (DSSDocument manifestDocument : archiveManifestDocuments) {
			ASiCEWithCAdESManifestParser parser = new ASiCEWithCAdESManifestParser(manifestDocument);
			descriptions.add(parser.getDescription());
		}

		return descriptions;
	}

}
