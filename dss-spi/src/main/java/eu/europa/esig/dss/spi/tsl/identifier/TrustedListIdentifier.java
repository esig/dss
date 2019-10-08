package eu.europa.esig.dss.spi.tsl.identifier;

import eu.europa.esig.dss.model.identifier.MultipleDigestIdentifier;
import eu.europa.esig.dss.spi.tsl.TLInfo;

public class TrustedListIdentifier extends MultipleDigestIdentifier {

	private static final long serialVersionUID = -527724241662081489L;

	public TrustedListIdentifier(TLInfo tlInfo) {
		super(tlInfo.getUrl().getBytes());
	}
	
	@Override
	public String asXmlId() {
		return "TL-" + super.asXmlId();
	}

}
