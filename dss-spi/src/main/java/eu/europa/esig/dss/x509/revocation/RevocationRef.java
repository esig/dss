package eu.europa.esig.dss.x509.revocation;

import java.io.Serializable;
import java.util.Set;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.utils.Utils;

public abstract class RevocationRef implements Serializable {

	private static final long serialVersionUID = 7313118727647264457L;

	protected Digest digest = null;
	
	protected Set<RevocationRefOrigin> origins;
	
	private String dssId;

	public Digest getDigest() {
		return digest;
	}
	
	public Set<RevocationRefOrigin> getOrigins() {
		return origins;
	}
	
	public void addOrigin(RevocationRefOrigin revocationRefOrigin) {
		origins.add(revocationRefOrigin);
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
		return digest.equals(o.getDigest());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((digest == null) ? 0 : digest.hashCode());
		return result;
	}

}
