package eu.europa.esig.dss.client.tsp;

import static org.junit.Assert.assertNotNull;

import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.client.SecureRandomNonceSource;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.TimestampDataLoader;

public class OnlineTSPSourceTest {

	private static final String TSA_URL = "http://tsa.belgium.be/connect";

	@Test
	public void testWithoutNonce() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
	}

	@Test
	public void testWithCommonDataLoader() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
		tspSource.setDataLoader(new CommonsDataLoader());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
	}

	@Test
	public void testWithTimestampDataLoader() {
		OnlineTSPSource tspSource = new OnlineTSPSource("http://tsa.sk.ee");
		tspSource.setDataLoader(new TimestampDataLoader()); // content-type is different

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, "Hello world".getBytes());
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, digest);
		assertNotNull(timeStampResponse);
	}

	@Test
	public void testWithNativeHTTPDataLoader() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
		tspSource.setDataLoader(new NativeHTTPDataLoader());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
	}

	@Test
	public void testWithNonce() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
		tspSource.setDataLoader(new NativeHTTPDataLoader());
		tspSource.setNonceSource(new SecureRandomNonceSource());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
	}

}
