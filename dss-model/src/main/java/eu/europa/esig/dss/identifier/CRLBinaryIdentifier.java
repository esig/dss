package eu.europa.esig.dss.identifier;

public class CRLBinaryIdentifier extends EncapsulatedRevocationTokenIdentifier {

	private static final long serialVersionUID = 3365111934665055383L;
	
	public CRLBinaryIdentifier(byte[] binaries) {
		super(binaries);
	}

}
