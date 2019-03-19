package eu.europa.esig.dss.x509.revocation.crl;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.RevocationOrigin;

public class CRLBinary {
	
	private final String base64Digest;
	
	private final byte[] binaries;
	
	private RevocationOrigin origin;
	
	public CRLBinary(byte[] binaries) {
		this.binaries = binaries;
		this.base64Digest = Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, binaries));
	}
	
	public CRLBinary(byte[] binaries, RevocationOrigin origin) {
		this(binaries);
		this.origin = origin;		
	}
	
	public String getBase64Digest() {
		return base64Digest;
	}
	
	public byte[] getBinaries() {
		return binaries;
	}
	
	public RevocationOrigin getOrigin() {
		return origin;
	}
	
	public void setOrigin(RevocationOrigin origin) {
		this.origin = origin;
	}

}
