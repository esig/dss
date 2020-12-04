package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.validation.ASiCEWithCAdESManifestParser;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESExtractResultUtils;
import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.signature.ASiCCounterSignatureHelper;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestFile;

import java.util.Collections;
import java.util.List;

/**
 * The class contains useful methods for ASiC with CAdES counter signature creation
 */
public class ASiCWithCAdESCounterSignatureHelper extends ASiCCounterSignatureHelper {

	/**
	 * The default constructor
	 *
	 * @param asicContainer {@link DSSDocument} representing an ASiC with CAdES container
	 */
	protected ASiCWithCAdESCounterSignatureHelper(DSSDocument asicContainer) {
		super(asicContainer);
	}

	@Override
	protected AbstractASiCContainerExtractor getASiCContainerExtractor() {
		return new ASiCWithCAdESContainerExtractor(asicContainer);
	}

	@Override
	protected DocumentValidator getDocumentValidator(DSSDocument signatureDocument) {
		return new CMSDocumentValidator(signatureDocument);
	}

	@Override
	protected List<DSSDocument> getDetachedDocuments(String signatureFilename) {
		ASiCExtractResult extractResult = getASiCExtractResult();
		DSSDocument signedDocument = ASiCWithCAdESExtractResultUtils.getSignedDocument(extractResult, signatureFilename);
		if (signedDocument != null) {
			return Collections.singletonList(signedDocument);
		}
		return Collections.emptyList();
	}
	
	@Override
	public ManifestFile getManifestFile(String signatureFilename) {
		ASiCExtractResult extractResult = getASiCExtractResult();
		DSSDocument signatureManifest = ASiCEWithCAdESManifestParser.getLinkedManifest(extractResult.getAllManifestDocuments(), signatureFilename);
		if (signatureManifest != null) {
			ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(signatureManifest);
			return manifestFile;
		}
		return null;
	}
	
	@Override
	protected void checkCounterSignaturePossible(DSSDocument signatureDocument) {
		super.checkCounterSignaturePossible(signatureDocument);
		
		if (ASiCWithCAdESExtractResultUtils.isCoveredByManifest(getASiCExtractResult(), signatureDocument.getName())) {
			throw new DSSException(String.format("The counter signature is not possible! "
					+ "Reason : a signature with a filename '%s' is covered by another manifest.", signatureDocument.getName()));
		}
	}

}
