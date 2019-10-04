package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.spi.tsl.dto.TrustServiceProvider;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.util.TimeDependentValues;

public class TrustProperties {

	private final String lotlUrl;
	private final String tlUrl;
	private final TrustServiceProvider trustServiceProvider;
	private final TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService;

	/**
	 * Constructor for extracted information from an "independant" trusted list
	 * 
	 * @param tlUrl
	 *                             the TL URL
	 * @param trustServiceProvider
	 *                             the trust service provider information
	 * @param trustService
	 *                             the current trust service
	 */
	public TrustProperties(String tlUrl, TrustServiceProvider trustServiceProvider,
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService) {
		this.lotlUrl = null;
		this.tlUrl = tlUrl;
		this.trustServiceProvider = trustServiceProvider;
		this.trustService = trustService;
	}

	/**
	 * Constructor for extracted information from trusted list which is linked to a
	 * LOTL
	 * 
	 * @param lotlUrl
	 *                             the LOTL Url
	 * @param tlUrl
	 *                             the TL URL
	 * @param trustServiceProvider
	 *                             the trust service provider information
	 * @param trustService
	 *                             the current trust service
	 */
	public TrustProperties(String lotlUrl, String tlUrl, TrustServiceProvider trustServiceProvider,
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService) {
		this.lotlUrl = lotlUrl;
		this.tlUrl = tlUrl;
		this.trustServiceProvider = trustServiceProvider;
		this.trustService = trustService;
	}

	public String getLotlUrl() {
		return lotlUrl;
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
