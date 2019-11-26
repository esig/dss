package eu.europa.esig.dss.spi.tsl.identifier;

import eu.europa.esig.dss.spi.tsl.PivotInfo;

public class PivotIdentifier extends AbstractTLIdentifier {

	private static final long serialVersionUID = 1005934627070196126L;

	public PivotIdentifier(PivotInfo pivotInfo) {
		super(pivotInfo);
	}
	
	@Override
	public String asXmlId() {
		return "P-" + super.asXmlId();
	}

}
