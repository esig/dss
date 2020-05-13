package eu.europa.esig.dss.pades.extension.suite;

import org.junit.jupiter.api.Tag;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.extension.suite.dss2058.AbstractDSS2058;

@Tag("slow")
public class DSS2058LTATest extends AbstractDSS2058 {

	@Override
	protected DSSDocument getDocumentToExtend() {
		return new InMemoryDocument(DSS2058LTATest.class.getResourceAsStream("/validation/dss-2058/dss-2058-LTA-test.pdf"));
	}

}
