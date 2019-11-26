package eu.europa.esig.dss.tsl.sync;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;

public class AcceptAllStrategy implements SynchronizationStrategy {

	@Override
	public boolean canBeSynchronized(TLInfo trustedList) {
		return true;
	}

	@Override
	public boolean canBeSynchronized(LOTLInfo listOfTrustedList) {
		return true;
	}

}
