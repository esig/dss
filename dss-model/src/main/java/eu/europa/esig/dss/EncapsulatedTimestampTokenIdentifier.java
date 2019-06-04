package eu.europa.esig.dss;

public class EncapsulatedTimestampTokenIdentifier extends EncapsulatedTokenIdentifier {

	private static final long serialVersionUID = 5005084271774302833L;

	public EncapsulatedTimestampTokenIdentifier(byte[] binaries) {
		super(binaries);
	}
	
	@Override
	public String asXmlId() {
		return "T-" + super.asXmlId();
	}

}
