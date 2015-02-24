package eu.europa.ec.markt.dss.cookbook.sources;

import eu.europa.ec.markt.dss.validation102853.tsl.TSLRefreshPolicy;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;

/**
 * This is the MOCK source which can load any trusted list.
 */
public class MockTSLCertificateSource extends TrustedListsCertificateSource {

	public MockTSLCertificateSource() {

		super();
		this.setTslRefreshPolicy(TSLRefreshPolicy.NEVER);
	}

	@Override
	public void loadAdditionalLists(final String... urls) {

		for (final String url : urls) {

			this.loadTSL(url, "MOCK", null);
		}
	}
}
