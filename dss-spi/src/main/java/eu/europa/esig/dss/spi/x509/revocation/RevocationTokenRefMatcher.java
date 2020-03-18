package eu.europa.esig.dss.spi.x509.revocation;

public interface RevocationTokenRefMatcher<R extends Revocation> {

	/**
	 * This method returns true if the reference is related to the provided token
	 * 
	 * @param token     the revocation token
	 * @param reference the revocation reference
	 * @return true if the reference refers to the token
	 */
	boolean match(RevocationToken<R> token, RevocationRef<R> reference);

}
