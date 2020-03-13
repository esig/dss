package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.identifier.TokenIdentifier;

public class RevocationTokenIdentifier extends TokenIdentifier {

	private static final long serialVersionUID = -6238848475533856942L;

	public RevocationTokenIdentifier(RevocationToken revocationToken) {
		this("R-", revocationToken);
	}
	
	RevocationTokenIdentifier(String prefix, RevocationToken revocationToken) {
		super(prefix, revocationToken);
	}

}
