package eu.europa.ec.markt.dss.mock;

import java.util.List;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;

public class MockSignatureTokenConnection extends AbstractSignatureTokenConnection {

	public MockSignatureTokenConnection() {
	}

	@Override
	public void close() {

	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
		return null;
	}

}
