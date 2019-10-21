package eu.europa.esig.dss.spi.tsl.identifier;

import eu.europa.esig.dss.model.identifier.MultipleDigestIdentifier;
import eu.europa.esig.dss.spi.tsl.TLInfo;

public abstract class AbstractTLIdentifier extends MultipleDigestIdentifier {

	private static final long serialVersionUID = -250692069626295484L;

	protected AbstractTLIdentifier(TLInfo tlInfo) {
		super(tlInfo.getUrl().getBytes());
	}

}
