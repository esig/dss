package eu.europa.esig.dss.cookbook.example.sources;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.x509.tsp.TSPSource;

/**
 * How to configure a Composite TSP Source.
 */
public class CompositeTSPSourceTest {

	@Test
	public void test() throws IOException {

		// tag::demo[]

		// Create a map with several TSPSources
		Map<String, TSPSource> tspSources = new HashMap<String, TSPSource>();
		tspSources.put("Poland", new OnlineTSPSource("http://time.certum.pl/"));
		tspSources.put("Belgium", new OnlineTSPSource("http://tsa.belgium.be/connect"));

		// Instantiate a new CompositeTSPSource and set the different sources
		CompositeTSPSource tspSource = new CompositeTSPSource();
		tspSource.setTspSources(tspSources);

		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
		final byte[] toDigest = "Hello world".getBytes("UTF-8");
		final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);

		// DSS will request the tsp sources (one by one) until getting a valid token.
		// If none of them succeed, a DSSException is thrown.
		final TimeStampToken tsr = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);

		System.out.println(DSSUtils.toHex(tsr.getEncoded()));

		// end::demo[]

		assertNotNull(tsr);
	}

}
