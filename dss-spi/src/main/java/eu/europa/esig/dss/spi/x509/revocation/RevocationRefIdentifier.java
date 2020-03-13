package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.Identifier;

public class RevocationRefIdentifier extends Identifier {

	private static final long serialVersionUID = 7648525025665164890L;

	public RevocationRefIdentifier(RevocationRef revocationRef) {
		this(revocationRef.getDigest());
	}
	
	protected RevocationRefIdentifier(final Digest digest) {
		super("R-", digest);
	}

}
