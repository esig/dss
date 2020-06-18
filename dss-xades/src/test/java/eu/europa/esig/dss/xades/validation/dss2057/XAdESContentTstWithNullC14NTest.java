package eu.europa.esig.dss.xades.validation.dss2057;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

public class XAdESContentTstWithNullC14NTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss2057/xades-content-tst-null-c14n.xml");
	}

}
