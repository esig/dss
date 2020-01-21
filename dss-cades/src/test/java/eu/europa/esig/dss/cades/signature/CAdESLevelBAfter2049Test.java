package eu.europa.esig.dss.cades.signature;

import java.util.Date;

import eu.europa.esig.dss.spi.DSSUtils;

public class CAdESLevelBAfter2049Test extends AbstractCAdESTestSigningTime {

	@Override
	protected Date getSigningTime() {
		// month is zero-based
		return DSSUtils.getUtcDate(2050, 0, 1);
	}

}
