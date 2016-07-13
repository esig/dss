package eu.europa.esig.dss.web;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.AbstractFactoryBean;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class DSSKeyStoreFactoryBean extends AbstractFactoryBean<KeyStoreCertificateSource> {

	private static final Logger logger = LoggerFactory.getLogger(DSSKeyStoreFactoryBean.class);

	private static final String ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER = "DSS_DATA_FOLDER";

	private String keyStoreType;
	private String keyStoreFilename;
	private String keyStorePassword;

	public void setKeyStoreType(String keyStoreType) {
		this.keyStoreType = keyStoreType;
	}

	public void setKeyStoreFilename(String keyStoreFilename) {
		this.keyStoreFilename = keyStoreFilename;
	}

	public void setKeyStorePassword(String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}

	@Override
	protected KeyStoreCertificateSource createInstance() throws Exception {
		File keystoreFile = getKeyStoreFile();
		if (keystoreFile.exists()) {
			logger.info("Keystore file found (" + keystoreFile.getAbsolutePath() + ")");
		} else {
			logger.info("Keystore file not found on server");
			logger.info("Copying keystore file from the war");

			InputStream is = null;
			OutputStream os = null;
			try {
				is = DSSKeyStoreFactoryBean.class.getResourceAsStream("/" + keyStoreFilename);
				os = new FileOutputStream(keystoreFile);
				IOUtils.copy(is, os);
			} catch (Exception e) {
				throw new DSSException("Unable to create the keystore on the server : " + e.getMessage(), e);
			} finally {
				Utils.closeQuietly(is);
				Utils.closeQuietly(os);
			}
		}
		return new KeyStoreCertificateSource(keystoreFile, keyStoreType, keyStorePassword);
	}

	@Override
	public Class<?> getObjectType() {
		return KeyStoreCertificateSource.class;
	}

	private File getKeyStoreFile() {
		String finalDataFolder = getDssDataFolder();

		File folder = new File(finalDataFolder);
		if (!folder.exists() || !folder.isDirectory()) {
			folder.mkdir();
		}

		String finalAbsoluteKeystoreFilepath = finalDataFolder + File.separatorChar + keyStoreFilename;
		File keystoreFile = new File(finalAbsoluteKeystoreFilepath);
		return keystoreFile;
	}

	private String getDssDataFolder() {
		String dssDataFolder = System.getProperty(ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER);
		if (Utils.isStringNotEmpty(dssDataFolder)) {
			logger.info(ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER + " found as system property : " + dssDataFolder);
			return dssDataFolder;
		}

		dssDataFolder = System.getenv(ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER);
		if (Utils.isStringNotEmpty(dssDataFolder)) {
			logger.info(ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER + " found as environment variable : " + dssDataFolder);
			return dssDataFolder;
		}

		logger.warn(ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER + " not defined (returns 'etc')");
		return "etc";
	}

}
