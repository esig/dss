package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceProvider;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.util.TimeDependentValues;

public class TrustProperties {

	private final Identifier lotlId;
	private final Identifier tlId;
	private final TrustServiceProvider trustServiceProvider;
	private final TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService;

	/**
	 * Constructor for extracted information from an "independent" trusted list
	 * 
	 * @param tlId
	 *                             the TL identifier
	 * @param trustServiceProvider
	 *                             the trust service provider information
	 * @param trustService
	 *                             the current trust service
	 */
	public TrustProperties(Identifier tlId, TrustServiceProvider trustServiceProvider,
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService) {
		this.lotlId = null;
		this.tlId = tlId;
		this.trustServiceProvider = trustServiceProvider;
		this.trustService = trustService;
	}

	/**
	 * Constructor for extracted information from trusted list which is linked to a
	 * LOTL
	 * 
	 * @param lotlId
	 *                             the LOTL identifier
	 * @param tlId
	 *                             the TL identifier
	 * @param trustServiceProvider
	 *                             the trust service provider information
	 * @param trustService
	 *                             the current trust service
	 */
	public TrustProperties(Identifier lotlId, Identifier tlId, TrustServiceProvider trustServiceProvider,
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService) {
		this.lotlId = lotlId;
		this.tlId = tlId;
		this.trustServiceProvider = trustServiceProvider;
		this.trustService = trustService;
	}

	public Identifier getLOTLIdentifier() {
		return lotlId;
	}

	public Identifier getTLIdentifier() {
		return tlId;
	}

	public TrustServiceProvider getTrustServiceProvider() {
		return trustServiceProvider;
	}

	public TimeDependentValues<TrustServiceStatusAndInformationExtensions> getTrustService() {
		return trustService;
	}

}
