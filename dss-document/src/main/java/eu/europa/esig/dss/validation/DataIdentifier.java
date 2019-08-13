package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.identifier.Identifier;

public final class DataIdentifier extends Identifier {

	private static final long serialVersionUID = -9023635708755646223L;

	public DataIdentifier(final byte[] data) {
		super(data);
	}

}
