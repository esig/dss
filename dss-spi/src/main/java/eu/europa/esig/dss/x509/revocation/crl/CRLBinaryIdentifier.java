package eu.europa.esig.dss.x509.revocation.crl;

import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.EncapsulatedRevocationTokenIdentifier;

public class CRLBinaryIdentifier extends EncapsulatedRevocationTokenIdentifier {

	private static final long serialVersionUID = 3365111934665055383L;
	
	public static CRLBinaryIdentifier build(byte[] binaries, RevocationOrigin origin) {
		return new CRLBinaryIdentifier(binaries, origin);
	}
	
	CRLBinaryIdentifier(byte[] binaries, RevocationOrigin origin) {
		super(binaries, origin);
	}

}
