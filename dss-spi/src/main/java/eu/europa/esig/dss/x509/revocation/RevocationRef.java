package eu.europa.esig.dss.x509.revocation;

import java.util.Arrays;
import java.util.Objects;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.RevocationOrigin;

public abstract class RevocationRef {

	protected DigestAlgorithm digestAlgorithm = null;
	protected byte[] digestValue = DSSUtils.EMPTY_BYTE_ARRAY;
	
	protected RevocationOrigin location;

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public byte[] getDigestValue() {
		return digestValue;
	}
	
	public RevocationOrigin getLocation() {
		return location;
	}
	
	@Override
	public String toString() {
		return Utils.toBase64(digestValue);
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof RevocationRef)) {
			return false;
		}
		RevocationRef o = (RevocationRef) obj;
		return digestAlgorithm.equals(o.getDigestAlgorithm()) && Arrays.equals(digestValue, o.getDigestValue()) &&
				location.equals(o.location);
	}

	@Override
	public int hashCode() {
		return Objects.hash(digestAlgorithm, digestValue, location);
	}

}
