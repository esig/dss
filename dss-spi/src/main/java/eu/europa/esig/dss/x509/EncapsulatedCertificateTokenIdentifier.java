package eu.europa.esig.dss.x509;

import eu.europa.esig.dss.identifier.MultipleDigestIdentifier;

public class EncapsulatedCertificateTokenIdentifier extends MultipleDigestIdentifier {

	private static final long serialVersionUID = 1075872220912450038L;

	public EncapsulatedCertificateTokenIdentifier(byte[] binaries) {
		super(binaries);
	}
	
	@Override
	public String asXmlId() {
		return "C-" + super.asXmlId();
	}

}
