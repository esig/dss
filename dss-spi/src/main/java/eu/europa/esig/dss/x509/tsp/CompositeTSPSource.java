package eu.europa.esig.dss.x509.tsp;

import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;

/**
 * This class allows to retrieve a timestamp with different sources. The composite will try all sources until to get a
 * non-empty response.
 * 
 * Be careful, all given tspSources MUST accept the same digest algorithm.
 * 
 */
public class CompositeTSPSource implements TSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(CompositeTSPSource.class);

	private Map<String, TSPSource> tspSources;

	/**
	 * This setter allows to provide multiple tspSources. Be careful, all given tspSources MUST accept the same digest
	 * algorithm.
	 * 
	 * @param tspSources
	 *            a {@code Map} of String and TSPSource with a label and its corresponding source
	 */
	public void setTspSources(Map<String, TSPSource> tspSources) {
		this.tspSources = tspSources;
	}

	@Override
	public TimeStampToken getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digestValue) throws DSSException {
		for (Entry<String, TSPSource> entry : tspSources.entrySet()) {
			String sourceKey = entry.getKey();
			TSPSource source = entry.getValue();
			LOG.debug("Trying to get timestamp with TSPSource '{}'", sourceKey);
			try {
				TimeStampToken token = source.getTimeStampResponse(digestAlgorithm, digestValue);
				if (token != null) {
					LOG.debug("Successfully retrieved timestamp with TSPSource '{}'", sourceKey);
					return token;
				}
			} catch (Exception e) {
				LOG.warn("Unable to retrieve the timestamp with TSPSource '{}' : {}", sourceKey, e.getMessage());
			}
		}
		throw new DSSException("Unable to retrieve the timestamp (" + tspSources.size() + " tries)");
	}

}
