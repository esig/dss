package eu.europa.esig.dss.asic.xades.signature;

import java.util.List;

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.signature.ASiCCounterSignatureHelper;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

public class ASiCWithXAdESCounterSignatureHelper extends ASiCCounterSignatureHelper {

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
