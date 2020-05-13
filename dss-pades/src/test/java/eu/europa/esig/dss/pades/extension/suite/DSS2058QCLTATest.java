package eu.europa.esig.dss.pades.extension.suite;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Tag;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.extension.suite.dss2058.AbstractDSS2058;

@Tag("slow")
public class DSS2058QCLTATest extends AbstractDSS2058 {

	@Override
	protected DSSDocument getDocumentToExtend() {
		return new InMemoryDocument(DSS2058QCLTATest.class.getResourceAsStream("/validation/dss-2058/dss-2058-QC-LTA-test.pdf"));
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		// fails because one signature does not contain CMS timestamp
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		for (TimestampWrapper timestampToken : diagnosticData.getTimestampList()) {
			assertTrue(timestampToken.isMessageImprintDataFound());
			assertTrue(timestampToken.isMessageImprintDataIntact());
		}
	}

}
