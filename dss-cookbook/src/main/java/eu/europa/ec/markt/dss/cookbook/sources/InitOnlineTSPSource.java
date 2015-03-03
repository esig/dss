package eu.europa.ec.markt.dss.cookbook.sources;

import java.io.IOException;

import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.validation102853.tsp.OnlineTSPSource;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * How to initialize online TSP source.
 */
public class InitOnlineTSPSource extends Cookbook {

	public static void main(String[] args) throws IOException {

		final String tspServer = "http://services.globaltrustfinder.com/adss/tsa";
		TSPSource tspSource = new OnlineTSPSource(tspServer);
		tspSource.setPolicyOid("1.2.3.4.5");

		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
		final byte[] toDigest = "digest value".getBytes();
		final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
		final TimeStampToken tsr = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);

		System.out.println(DSSUtils.toHex(tsr.getEncoded()));
	}
}
