package eu.europa.esig.dss;

import eu.europa.esig.dss.x509.RevocationOrigin;

public class EncapsulatedRevocationTokenIdentifier extends EncapsulatedTokenIdentifier {

	private static final long serialVersionUID = -562828035596645649L;

	public EncapsulatedRevocationTokenIdentifier(byte[] binaries) {
		super(binaries);
	}
	
	protected EncapsulatedRevocationTokenIdentifier(byte[] binaries, RevocationOrigin origin) {
		super(binaries, origin);
	}
	
	@Override
	public String asXmlId() {
		return "R-" + super.asXmlId();
	}
	
}
