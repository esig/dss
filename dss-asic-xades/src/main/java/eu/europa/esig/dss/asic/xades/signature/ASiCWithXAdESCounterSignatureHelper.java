package eu.europa.esig.dss.asic.xades.signature;

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

}
