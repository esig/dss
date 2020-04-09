package eu.europa.esig.dss.xades.validation.dss1334;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

public class DSS1334CorrectNameTest extends AbstractXAdESTestValidation {

	private static final DSSDocument ORIGINAL_FILE = new FileDocument("src/test/resources/validation/dss1334/simple-test.xml");

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss1334/simple-test-signed-xades-baseline-b.xml");
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Collections.singletonList(ORIGINAL_FILE);
	}

}
