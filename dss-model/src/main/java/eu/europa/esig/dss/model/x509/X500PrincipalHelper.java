package eu.europa.esig.dss.model.x509;

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.enumerations.X520Attributes;

public class X500PrincipalHelper {

	private final X500Principal principal;

	public X500PrincipalHelper(X500Principal principal) {
		this.principal = principal;
	}

	public X500Principal getPrincipal() {
		return principal;
	}

	public String getCanonical() {
		return principal.getName(X500Principal.CANONICAL);
	}

	public String getRFC2253() {
		return principal.getName(X500Principal.RFC2253);
	}

	public String getPrettyPrintRFC2253() {
		return principal.getName(X500Principal.RFC2253, X520Attributes.OID_DESCRIPTION);
	}

	public byte[] getEncoded() {
		return principal.getEncoded();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((principal == null) ? 0 : principal.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		X500PrincipalHelper other = (X500PrincipalHelper) obj;
		if (principal == null) {
			if (other.principal != null) {
				return false;
			}
		} else if (!principal.equals(other.principal)) {
			return false;
		}
		return true;
	}

}
