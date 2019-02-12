package eu.europa.esig.dss.x509.revocation;

import eu.europa.esig.dss.x509.RevocationToken;

/**
 * Sub-interface for online sources of {@link RevocationToken}s
 */
public interface OnlineSource<T extends RevocationToken> extends RevocationSource<T> {

}
