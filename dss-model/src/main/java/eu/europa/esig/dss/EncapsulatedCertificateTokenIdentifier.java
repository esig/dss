package eu.europa.esig.dss;

public class EncapsulatedCertificateTokenIdentifier extends EncapsulatedTokenIdentifier {

	private static final long serialVersionUID = 1075872220912450038L;

	public EncapsulatedCertificateTokenIdentifier(byte[] binaries) {
		super(binaries);
	}
	
	@Override
	public String asXmlId() {
		return "C-" + super.asXmlId();
	}

}
