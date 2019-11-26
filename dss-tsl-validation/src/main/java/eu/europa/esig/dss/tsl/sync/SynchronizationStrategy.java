package eu.europa.esig.dss.tsl.sync;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;

public interface SynchronizationStrategy {

	/**
	 * Returns true if the certificates from the trusted list can be synchronized
	 * 
	 * @param trustedList
	 *                    the trusted list to be tested
	 * @return true if the trusted list can be synchronized
	 */
	boolean canBeSynchronized(TLInfo trustedList);

	/**
	 * Returns true if the certificates from the list of trusted lists and its
	 * trusted list can be synchronized
	 * 
	 * @param listOfTrustedList
	 *                          the list of trusted lists to be tested
	 * @return true if the list of trusted lists can be synchronized
	 */
	boolean canBeSynchronized(LOTLInfo listOfTrustedList);

}
