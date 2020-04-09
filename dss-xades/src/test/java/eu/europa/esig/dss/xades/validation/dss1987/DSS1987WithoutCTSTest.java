package eu.europa.esig.dss.xades.validation.dss1987;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class DSS1987WithoutCTSTest extends AbstractDSS1987Test {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss1987/data2sign-signed-xades-enveloped-baseline-lta.xml");
	}

}
