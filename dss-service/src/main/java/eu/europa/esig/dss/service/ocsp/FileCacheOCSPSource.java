package eu.europa.esig.dss.service.ocsp;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.FileRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * OCSP Source that stores its OCSP responses on the file system.
 */
public class FileCacheOCSPSource extends FileRevocationSource<OCSP> implements OCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(FileCacheOCSPSource.class);

	private static final long serialVersionUID = 1L;

	/**
	 * @param cacheDirectory {@link File} the directory where cached OCSP files will
	 *                       be stored
	 */
	public FileCacheOCSPSource(final File cacheDirectory) {
		super(cacheDirectory);
	}

	/**
	 * @param cacheDirectory path of directory where cached OCSP files will be
	 *                       stored
	 */
	public FileCacheOCSPSource(final String cacheDirectory) {
		super(cacheDirectory);
	}

	@Override
	protected RevocationToken<OCSP> reconstructTokenFromEncodedData(byte[] encodedData, CertificateToken certificateToken,
			CertificateToken issuerCertToken) {
		try {
			OCSPResp ocspResp = new OCSPResp(encodedData);

			OCSPRespStatus status = OCSPRespStatus.fromInt(ocspResp.getStatus());
			if (!OCSPRespStatus.SUCCESSFUL.equals(status)) {
				LOG.warn("OCSP Response status is not successful: {} for certificate: {}",
						status, certificateToken.getDSSIdAsString());
				return null;
			}

			Object responseObject = ocspResp.getResponseObject();
			if (!(responseObject instanceof BasicOCSPResp)) {
				LOG.warn("OCSP Response Object is not of type BasicOCSPResp for certificate: {}",
						certificateToken.getDSSIdAsString());
				return null;
			}

			BasicOCSPResp basicOCSPResp = (BasicOCSPResp) responseObject;
			SingleResp latestSingleResponse = DSSRevocationUtils.getLatestSingleResponse(
					basicOCSPResp, certificateToken, issuerCertToken);

			if (latestSingleResponse != null) {
				OCSPToken token = new OCSPToken(basicOCSPResp, latestSingleResponse, certificateToken, issuerCertToken);
				token.setExternalOrigin(RevocationOrigin.CACHED);
				return token;
			} else {
				LOG.warn("No valid SingleResp found in OCSP response for certificate: {}",
						certificateToken.getDSSIdAsString());
				return null;
			}
		} catch (Exception e) {
			LOG.error("Failed to create OCSP token from cached data for certificate '{}': {}",
					certificateToken.getDSSIdAsString(), e.getMessage());
			return null;
		}
	}

	@Override
	protected String getFileExtension() {
		return ".ocsp";
	}

	@Override
	protected String getRevocationTokenKey(CertificateToken certificateToken, String revocationAccessUrl) {
		return DSSUtils.getNormalizedString(revocationAccessUrl);
	}

	@Override
	protected List<String> getRevocationAccessUrls(CertificateToken certificateToken) {
		return CertificateExtensionsUtils.getOCSPAccessUrls(certificateToken);
	}

	@Override
	protected List<String> initRevocationTokenKeys(CertificateToken certificateToken) {
		final List<String> revocationKeys = new ArrayList<>();
		final List<String> ocspUrls = getRevocationAccessUrls(certificateToken);
		for (String ocspUrl : ocspUrls) {
			revocationKeys.add(getRevocationTokenKey(certificateToken, ocspUrl));
		}
		return revocationKeys;
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken,
			boolean forceRefresh) {
		return (OCSPToken) super.getRevocationToken(certificateToken, issuerCertificateToken, forceRefresh);
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return this.getRevocationToken(certificateToken, issuerCertificateToken, false);
	}

}
