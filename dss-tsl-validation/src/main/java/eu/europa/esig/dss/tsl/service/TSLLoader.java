package eu.europa.esig.dss.tsl.service;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.concurrent.Callable;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.tsl.TSLValidationModel;

public class TSLLoader implements Callable<TSLValidationModel> {

	private static final Logger logger = LoggerFactory.getLogger(LOTLLoader.class);
	private static final File TMP_FOLDER = new File(System.getProperty("java.io.tmpdir"));

	private DataLoader dataLoader;
	private TSLParser parser;
	private String urlToLoad;

	public TSLLoader(DataLoader dataLoader, TSLParser parser, String urlToLoad) {
		super();
		this.dataLoader = dataLoader;
		this.parser = parser;
		this.urlToLoad = urlToLoad;
	}

	@Override
	public TSLValidationModel call() throws Exception {
		String sha1URL = getSHA1(urlToLoad);

		InputStream is = null;
		byte[] byteArray = null;
		File tempFile = new File(TMP_FOLDER, sha1URL);
		if (tempFile.exists()) {
			logger.info("Temp file for url '" + urlToLoad + "' already exists");
			is = new FileInputStream(tempFile);
			byteArray = IOUtils.toByteArray(new FileInputStream(tempFile));
		} else {
			byteArray = dataLoader.get(urlToLoad);
			is = new ByteArrayInputStream(byteArray);
			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(tempFile);
				IOUtils.write(byteArray, fos);
			} catch (Exception e) {
				logger.error("Unable to store lotl binaries in tmp : " + e.getMessage(), e);
			} finally {
				IOUtils.closeQuietly(fos);
			}
		}

		TSLValidationModel model = parser.parseTSL(is);
		model.setUrl(urlToLoad);
		model.setSha1Url(sha1URL);
		model.setSha1FileContent(getSHA1(byteArray));
		model.setFilepath(tempFile.getAbsolutePath());
		return model;
	}

	private String getSHA1(String data) {
		return getSHA1(data.getBytes());
	}

	private String getSHA1(byte[] data) {
		return DatatypeConverter.printHexBinary(DSSUtils.digest(DigestAlgorithm.SHA1, data));
	}

}
