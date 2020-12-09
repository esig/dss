package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.signature.ASiCCounterSignatureHelper;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

import java.util.List;

/**
 * The class contains useful methods for ASiC with XAdES counter signature creation
 */
public class ASiCWithXAdESCounterSignatureHelper extends ASiCCounterSignatureHelper {

	/**
	 * The default constructor
	 *
	 * @param asicContainer {@link DSSDocument} representing an ASiC with CAdES container
	 */
	protected ASiCWithXAdESCounterSignatureHelper(DSSDocument asicContainer) {
		super(asicContainer);
	}

	@Override
	protected AbstractASiCContainerExtractor getASiCContainerExtractor() {
		return new ASiCWithXAdESContainerExtractor(asicContainer);
	}

	@Override
	protected DocumentValidator getDocumentValidator(DSSDocument signatureDocument) {
		return new XMLDocumentValidator(signatureDocument);
	}

	@Override
	protected List<DSSDocument> getDetachedDocuments(String signatureFilename) {
		// return all found documents (any document can be signed)
		ASiCExtractResult extractResult = getASiCExtractResult();
		return extractResult.getAllDocuments();
	}

}
