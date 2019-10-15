package eu.europa.esig.dss.spi.tsl.identifier;

import eu.europa.esig.dss.spi.tsl.TLInfo;

public class TrustedListIdentifier extends AbstractTLIdentifier {

	private static final long serialVersionUID = -527724241662081489L;

	public TrustedListIdentifier(TLInfo tlInfo) {
		super(tlInfo);
	}
	
	@Override
	public String asXmlId() {
		return "TL-" + super.asXmlId();
	}

}
