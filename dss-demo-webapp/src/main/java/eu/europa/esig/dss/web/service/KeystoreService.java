package eu.europa.esig.dss.web.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.annotation.PostConstruct;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.web.model.CertificateDTO;
import eu.europa.esig.dss.x509.CertificateToken;

@Component
public class KeystoreService {

	private static final Logger logger = LoggerFactory.getLogger(KeystoreService.class);

	private static final String ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER = "DSS_DATA_FOLDER";

	@Autowired
	private ResourceLoader resourceLoader;

	@Value("${keystore.type}")
	private String keyStoreType;

	@Value("${keystore.filename}")
	private String keyStoreFilename;

	@Value("${keystore.password}")
	private String keyStorePassword;

	private KeyStore store;

	@PostConstruct
	public void initServer() {
		File keystoreFile = getKeyStoreFile();
		if (keystoreFile.exists()) {
			logger.info("Keystore file found");
		} else {
			logger.info("Keystore file not found on server");
			logger.info("Copying keystore file from the war");

			InputStream is = null;
			OutputStream os = null;
			try {
				Resource resource = resourceLoader.getResource(ResourceLoader.CLASSPATH_URL_PREFIX + keyStoreFilename);
				is = resource.getInputStream();
				os = new FileOutputStream(keystoreFile);
				IOUtils.copy(is, os);
			} catch (Exception e) {
				logger.error("Unable to copy keystore file : " + e.getMessage(), e);
				throw new DSSException("Unable to create the keystore on the server");
			} finally {
				IOUtils.closeQuietly(is);
				IOUtils.closeQuietly(os);
			}
		}

	}

	public KeyStore getKeyStore() {
		if (store == null) {
			InputStream is = null;
			try {
				store = KeyStore.getInstance(keyStoreType);
				is = new FileInputStream(getKeyStoreFile());
				if (is != null) {
					store.load(is, keyStorePassword.toCharArray());
				}
			} catch (Exception e) {
				logger.error("Unable to read keystore : " + e.getMessage(), e);
			} finally {
				IOUtils.closeQuietly(is);
			}
		}
		return store;
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
		if (StringUtils.isNotEmpty(dssDataFolder)) {
			logger.info(ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER + " found as system property : " + dssDataFolder);
			return dssDataFolder;
		}

		dssDataFolder = System.getenv(ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER);
		if (StringUtils.isNotEmpty(dssDataFolder)) {
			logger.info(ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER + " found as environment variable : " + dssDataFolder);
			return dssDataFolder;
		}

		logger.warn(ENVIRONMENT_VARIABLE_DSS_DATA_FOLDER + " not defined (return etc)");
		return "etc";
	}

	public void addCertificate(CertificateToken certificateToken) {
		try {
			KeyStore keyStore = getKeyStore();
			keyStore.setCertificateEntry(certificateToken.getDSSIdAsString(), certificateToken.getCertificate());
			persistKeyStore(keyStore);
		} catch (Exception e) {
			logger.error("Unable to add certificate to the keystore : " + e.getMessage(), e);
		}
	}

	private void persistKeyStore(KeyStore keyStore) {
		OutputStream os = null;
		try {
			os = new FileOutputStream(getKeyStoreFile());
			keyStore.store(os, keyStorePassword.toCharArray());
		} catch (Exception e) {
			logger.error("Unable to persist the keystore : " + e.getMessage(), e);
		} finally {
			IOUtils.closeQuietly(os);
		}
	}

	public void deleteCertificate(String dssId) {
		KeyStore keyStore = getKeyStore();
		try {
			if (keyStore.containsAlias(dssId)) {
				keyStore.deleteEntry(dssId);
				persistKeyStore(keyStore);
				logger.info("Certificate with ID " + dssId + " successfuly removed from the keystore");
			} else {
				logger.warn("Certificate " + dssId + " not found in the keystore");
			}
		} catch (Exception e) {
			logger.error("Unable to delete certificate from the keystore : " + e.getMessage(), e);
		}
	}

	public List<CertificateDTO> loadCertificatesFromKeryStore() {
		List<CertificateDTO> list = new ArrayList<CertificateDTO>();

		KeyStore keyStore = getKeyStore();
		try {
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (keyStore.isCertificateEntry(alias)) {
					Certificate certificate = keyStore.getCertificate(alias);
					CertificateToken certificateToken = DSSUtils.loadCertificate(certificate.getEncoded());
					list.add(getCertificateDTO(certificateToken));
				}
			}
		} catch (Exception e) {
			logger.error("Unable to retrieve certificates from the keystore : " + e.getMessage(), e);
		}
		return list;
	}

	public CertificateDTO getCertificateDTO(CertificateToken certificate) {
		CertificateDTO dto = new CertificateDTO();

		dto.setDssId(certificate.getDSSIdAsString());
		dto.setIssuerName(certificate.getIssuerX500Principal().getName());
		dto.setSubjetName(certificate.getSubjectX500Principal().getName());
		dto.setNotBefore(certificate.getNotBefore());
		dto.setNotAfter(certificate.getNotAfter());

		byte[] digestSHA256 = DSSUtils.digest(DigestAlgorithm.SHA256, certificate.getEncoded());
		byte[] digestSHA1 = DSSUtils.digest(DigestAlgorithm.SHA1, certificate.getEncoded());

		dto.setSha256Hex(getPrintableHex(digestSHA256));
		dto.setSha1Hex(getPrintableHex(digestSHA1));
		dto.setSha256Base64(Base64.encodeBase64String(digestSHA256));
		dto.setSha1Base64(Base64.encodeBase64String(digestSHA1));

		return dto;
	}

	/**
	 * This method adds space every two characters to the hexadecimal encoded digest
	 *
	 * @param digest
	 * @return
	 */
	private String getPrintableHex(byte[] digest) {
		String hexString = Hex.encodeHexString(digest);
		return hexString.replaceAll("..", "$0 ");
	}

}
