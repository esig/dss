package eu.europa.esig.dss.web.service;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.annotation.Resource;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamSource;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.web.model.CertificateDTO;
import eu.europa.esig.dss.x509.CertificateToken;

@Component
public class KeystoreService {

	private static final Logger logger = LoggerFactory.getLogger(KeystoreService.class);

	@Autowired
	@Resource(name = "keystore.source")
	private InputStreamSource source;

	@Value("${keystore.password}")
	private String keyStorePassword;

	public List<CertificateDTO> loadCertificatesFromKeryStore() {
		List<CertificateDTO> list = new ArrayList<CertificateDTO>();

		InputStream stream = null;
		try {
			KeyStore store = KeyStore.getInstance("JKS");

			stream = source.getInputStream();
			if (stream != null) {
				store.load(stream, keyStorePassword.toCharArray());

				Enumeration<String> aliases = store.aliases();
				while (aliases.hasMoreElements()) {
					String alias = aliases.nextElement();
					if (store.isCertificateEntry(alias)) {
						Certificate certificate = store.getCertificate(alias);
						CertificateToken certificateToken = DSSUtils.loadCertificate(certificate.getEncoded());
						list.add(getCertificateDTO(certificateToken));
					}
				}
			}
		} catch (Exception e) {
			logger.error("Unable to load keystore : " + e.getMessage(), e);
		} finally {
			IOUtils.closeQuietly(stream);
		}

		return list;
	}

	public CertificateDTO getCertificateDTO(byte[] certificateBytes) {
		CertificateToken certificate = DSSUtils.loadCertificate(certificateBytes);
		return getCertificateDTO(certificate);
	}

	private CertificateDTO getCertificateDTO(CertificateToken certificate) {
		CertificateDTO dto = new CertificateDTO();

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
