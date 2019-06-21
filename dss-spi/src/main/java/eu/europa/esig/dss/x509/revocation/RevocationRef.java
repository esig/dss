package eu.europa.esig.dss.x509.revocation;

import java.util.Objects;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.RevocationOrigin;

public abstract class RevocationRef {

	protected Digest digest = null;
	
	protected RevocationOrigin origin;
	
	private String dssId;

	public Digest getDigest() {
		return digest;
	}
	
	public RevocationOrigin getOrigin() {
		return origin;
	}
	
	/**
	 * Returns revocation reference {@link String} id
	 * @return {@link String} id
	 */
	public String getDSSIdAsString() {
		if (dssId == null) {
			dssId = "R-" + digest.getHexValue().toUpperCase();
		}
		return dssId;
	}
	
	@Override
	public String toString() {
		return Utils.toBase64(digest.getValue());
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
		return digest.equals(o.getDigest()) && origin.equals(o.origin);
	}

	@Override
	public int hashCode() {
		return Objects.hash(digest, origin);
	}

}
