package eu.europa.esig.dss.tsl.summary;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;

/**
 * Defines a LOTL with a link between its TLs and pivots
 * 
 */
public class LinkedLOTL {
	
	private final LOTLSource lotlSource;
	
	private final List<TLSource> tlSources;
	
	private final List<LOTLSource> pivots;
	
	public LinkedLOTL(final LOTLSource lotlSource, final List<TLSource> tlSources) {
		this(lotlSource, tlSources, Collections.emptyList());
	}
	
	public LinkedLOTL(final LOTLSource lotlSource, final List<TLSource> tlSources, final List<LOTLSource> pivots) {
		this.lotlSource = lotlSource;
		this.tlSources = tlSources;
		this.pivots = pivots;
	}

	public LOTLSource getLotlSource() {
		return lotlSource;
	}

	public List<TLSource> getTlSources() {
		return tlSources;
	}

	public List<LOTLSource> getPivots() {
		return pivots;
	}

}
