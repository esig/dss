package eu.europa.esig.dss.spi.tsl.identifier;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;

public class LOTLIdentifier extends TrustedListIdentifier {

	private static final long serialVersionUID = 8038937216737566183L;

	public LOTLIdentifier(LOTLInfo lotlInfo) {
		super(lotlInfo);
	}
	
	@Override
	public String asXmlId() {
		return "LOTL-" + super.asXmlId();
	}

}
