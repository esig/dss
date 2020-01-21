package eu.europa.esig.dss.cades.signature;

import java.util.Date;

import eu.europa.esig.dss.spi.DSSUtils;

public class CAdESLevelBBefore1950Test extends AbstractCAdESTestSigningTime {

	@Override
	protected Date getSigningTime() {
		// month is zero-based
		return DSSUtils.getUtcDate(1949, 11, 31);
	}

}
