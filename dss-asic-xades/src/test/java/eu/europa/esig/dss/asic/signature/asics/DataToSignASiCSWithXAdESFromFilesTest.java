package eu.europa.esig.dss.asic.signature.asics;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.utils.Utils;

public class DataToSignASiCSWithXAdESFromFilesTest {

	private static final Logger LOG = LoggerFactory.getLogger(DataToSignASiCSWithXAdESFromFilesTest.class);

	@Test
	public void zipContentEquals() throws Exception {
		Date now = new Date();
		ASiCParameters asicParameters = new ASiCParameters();
		List<DSSDocument> filesToBeSigned = new ArrayList<DSSDocument>();
		filesToBeSigned.add(new InMemoryDocument("Hello".getBytes(), "test.xml"));
		filesToBeSigned.add(new InMemoryDocument("Bye".getBytes(), "test2.xml"));
		DataToSignASiCSWithXAdESFromFiles dataToSign = new DataToSignASiCSWithXAdESFromFiles(filesToBeSigned, now, asicParameters);
		assertNotNull(dataToSign);

		List<DSSDocument> toBeSigned = dataToSign.getToBeSigned();
		assertEquals(1, toBeSigned.size());
		DSSDocument dssDocument = toBeSigned.get(0);
		assertEquals("package.zip", dssDocument.getName());

		byte[] byteArray = DSSUtils.toByteArray(dssDocument);
		LOG.info(new String(byteArray));
		String base64 = Utils.toBase64(byteArray);
		LOG.info(base64);

		String digest = dssDocument.getDigest(DigestAlgorithm.SHA256);

		LOG.info(digest);

		Thread.sleep(2000);

		DataToSignASiCSWithXAdESFromFiles dataToSign2 = new DataToSignASiCSWithXAdESFromFiles(filesToBeSigned, now, asicParameters);
		DSSDocument twice = dataToSign2.getToBeSigned().get(0);

		String digestTwice = twice.getDigest(DigestAlgorithm.SHA256);

		String base64twice = Utils.toBase64(DSSUtils.toByteArray(twice));
		LOG.info(base64twice);
		LOG.info(digestTwice);

		assertEquals(base64, base64twice);
		assertTrue(Utils.areStringsEqual(digest, digestTwice));

	}
}
