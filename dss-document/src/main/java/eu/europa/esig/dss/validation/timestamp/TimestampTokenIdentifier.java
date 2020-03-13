package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.model.identifier.TokenIdentifier;

public final class TimestampTokenIdentifier extends TokenIdentifier {

	private static final long serialVersionUID = 4260120806950705848L;

	public TimestampTokenIdentifier(TimestampToken timestampToken) {
		super("T-", timestampToken);
	}

}
