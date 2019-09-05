package eu.europa.esig.dss.model.identifier;

public class EncapsulatedRevocationTokenIdentifier extends MultipleDigestIdentifier {

	private static final long serialVersionUID = -562828035596645649L;

	public EncapsulatedRevocationTokenIdentifier(byte[] binaries) {
		super(binaries);
	}
	
	@Override
	public String asXmlId() {
		return "R-" + super.asXmlId();
	}
	
}
