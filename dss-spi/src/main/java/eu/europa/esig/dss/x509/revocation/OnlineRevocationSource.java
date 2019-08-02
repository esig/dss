package eu.europa.esig.dss.x509.revocation;

import eu.europa.esig.dss.client.http.DataLoader;

/**
 * Sub-interface for online sources of {@link RevocationToken}s
 */
public interface OnlineRevocationSource<T extends RevocationToken> extends RevocationSource<T> {
	
	/**
	 * Set the DataLoader to use for querying a revocation server.
	 *
	 * @param dataLoader
	 *            the component that allows to retrieve a revocation response using
	 *            HTTP.
	 */
	void setDataLoader(final DataLoader dataLoader);

}
