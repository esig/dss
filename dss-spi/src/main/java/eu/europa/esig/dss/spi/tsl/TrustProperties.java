package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.spi.tsl.dto.TrustServiceProvider;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.util.TimeDependentValues;

public class TrustProperties {

	private final String tlUrl;
	private final TrustServiceProvider trustServiceProvider;
	private final TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService;

	public TrustProperties(String tlUrl, TrustServiceProvider trustServiceProvider,
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService) {
		this.tlUrl = tlUrl;
		this.trustServiceProvider = trustServiceProvider;
		this.trustService = trustService;
	}

	public String getTlUrl() {
		return tlUrl;
	}

	public TrustServiceProvider getTrustServiceProvider() {
		return trustServiceProvider;
	}

	public TimeDependentValues<TrustServiceStatusAndInformationExtensions> getTrustService() {
		return trustService;
	}

}
