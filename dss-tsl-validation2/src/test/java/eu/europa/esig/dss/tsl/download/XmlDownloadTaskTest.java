package eu.europa.esig.dss.tsl.download;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;

public class XmlDownloadTaskTest {

	@Test
	public void nullResult() {
		Map<String, byte[]> dataMap = new HashMap<String, byte[]>();

		dataMap.put("null", null);
		dataMap.put("empty-array", new byte[] {});
		dataMap.put("0", new byte[] { 0 });

		DataLoader dataLoader = new MemoryDataLoader(dataMap);
		for (String url : dataMap.keySet()) {
			XmlDownloadTask task = new XmlDownloadTask(dataLoader, url);
			assertNull(task.get());
		}
	}

	@Test
	public void nonNullResults() {
		Map<String, byte[]> dataMap = new HashMap<String, byte[]>();

		byte[] sampleByteArray = DSSUtils.toByteArray(new FileDocument(new File("src/test/resources/sample.xml")));
		dataMap.put("sample", sampleByteArray);
		dataMap.put("sample-spaces", DSSUtils.toByteArray(new FileDocument(new File("src/test/resources/sample-spaces.xml"))));
		dataMap.put("sample-comment", DSSUtils.toByteArray(new FileDocument(new File("src/test/resources/sample-comment.xml"))));
		byte[] sampleWithBomByteArray = DSSUtils.toByteArray(new FileDocument(new File("src/test/resources/sample-bom.xml")));
		dataMap.put("sample-bom", sampleWithBomByteArray);

		assertNotEquals(DSSUtils.getMD5Digest(sampleByteArray), DSSUtils.getMD5Digest(sampleWithBomByteArray));

		DataLoader dataLoader = new MemoryDataLoader(dataMap);
		XmlDownloadResult first = null;
		for (String url : dataMap.keySet()) {
			XmlDownloadTask task = new XmlDownloadTask(dataLoader, url);
			XmlDownloadResult downloadResult = task.get();
			assertNotNull(downloadResult);
			assertNotNull(downloadResult.getContent());
			assertNotNull(downloadResult.getDigest());
			assertNotNull(downloadResult.getDigest().getAlgorithm());
			assertNotNull(downloadResult.getDigest().getValue());
			assertEquals(url, downloadResult.getUrl());
			if (first == null) {
				first = downloadResult;
			} else {
				assertEquals(first.getDigest(), downloadResult.getDigest());
			}
		}

		dataMap.put("sample-diff", DSSUtils.toByteArray(new FileDocument(new File("src/test/resources/sample-diff.xml"))));
		XmlDownloadTask task = new XmlDownloadTask(new MemoryDataLoader(dataMap), "sample-diff");
		XmlDownloadResult downloadResultDiff = task.get();
		assertNotNull(downloadResultDiff);
		assertNotNull(downloadResultDiff.getDigest());
		assertNotEquals(first.getDigest(), downloadResultDiff.getDigest());
	}

}
