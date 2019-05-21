package eu.europa.esig.dss.x509.revocation.crl;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.x509.RevocationOrigin;

public class CRLBinaryIdentifier extends EncapsulatedRevocationTokenIdentifier {

	private static final long serialVersionUID = 3365111934665055383L;
	
	public static CRLBinaryIdentifier build(byte[] binaries, RevocationOrigin origin) {
		return new CRLBinaryIdentifier(binaries, origin);
	}
	
	CRLBinaryIdentifier(byte[] binaries, RevocationOrigin origin) {
		super(binaries, origin);
	}
	
	public byte[] getDigestValue(DigestAlgorithm digestAlgorithm) {
		byte[] digestValue = super.getDigestValue(digestAlgorithm);
		if (digestValue == null) {
			digestValue = DSSUtils.digest(digestAlgorithm, getBinaries());
			digestMap.put(digestAlgorithm, digestValue);
		}
		return digestValue;
	}

}
