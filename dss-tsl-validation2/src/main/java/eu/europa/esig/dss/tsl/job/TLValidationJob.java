package eu.europa.esig.dss.tsl.job;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;

public class TLValidationJob {

	/**
	 * Configured DataLoader to retrieve online data (usually an instance of the
	 * {@link CommonDaLoader} with the proxy,... configuration
	 */
	private DataLoader onlineDataLoader;

	/**
	 * Array of zero, one or more Trusted List (TL) sources.
	 * 
	 * These trusted lists are not referenced in a List Of Trusted Lists (LOTL)
	 */
	private TLSource[] trustedListSources;

	/**
	 * Array of zero, one or more List Of Trusted List (LOTL) sources.
	 */
	private LOTLSource[] listOfTrustedListSources;

	public void setOnlineDataLoader(DataLoader onlineDataLoader) {
		this.onlineDataLoader = onlineDataLoader;
	}

	public void setTrustedListSources(TLSource... trustedListSources) {
		this.trustedListSources = trustedListSources;
	}

	public void setListOfTrustedListSources(LOTLSource... listOfTrustedListSources) {
		this.listOfTrustedListSources = listOfTrustedListSources;
	}

	public void init() {
//		refresh(cacheDataLoader);
	}

	public void refresh() {
		refresh(onlineDataLoader);
	}

	private void refresh(DataLoader dataLoader) {

		List<TLSource> currentTLSources = new ArrayList<TLSource>();
		if (trustedListSources != null) {
			currentTLSources = Arrays.asList(trustedListSources);
		}

		// Execute all LOTLs
		if (listOfTrustedListSources != null) {
			executeLOTLSourcesAnalysis(Arrays.asList(listOfTrustedListSources), dataLoader);

			// extract TLSources from cached LOTLs
		}

		// And then, execute all TLs (manual configs + TLs from LOTLs)
		executeTLSourcesAnalysis(currentTLSources, dataLoader);

		// alerts()

		// TLCerSource sync + cache sync if needed

		// cache cleaner (remove TO_BE_DELETED entries)
	}

	private void executeLOTLSourcesAnalysis(List<LOTLSource> lotlSources, DataLoader dataLoader) {
		// get cache contents

		for (LOTLSource lotlSource : lotlSources) {
//			execute();
		}

		for (LOTLSource lotlSource : lotlSources) {
//			get();
		}

		// update caches

		// Analyse introduced changes for TLs + adapt cache for TLs (EXPIRED)
	}

	private void executeTLSourcesAnalysis(List<TLSource> tlSources, DataLoader dataLoader) {
		// get cache contents

		for (TLSource tlSource : tlSources) {
//			execute();
		}

		for (TLSource tlSource : tlSources) {
//			get();
		}

		// update caches
	}

}
