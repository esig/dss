package eu.europa.esig.dss.pades.validation.suite.dss818;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class DSS818ADOTest extends AbstractDSS818Test {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-818/Signature-P-IT_ADO-1 (HASH_FAILURE) (ECDSA).pdf"));
	}

}
