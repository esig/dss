package eu.europa.esig.dss.client.crl;

import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.CRLToken;

public class CRLCache implements CRLSource {

	private static final long serialVersionUID = 3634641793103989471L;

	private static final Logger LOG = LoggerFactory.getLogger(JdbcCRLCacheRepository.class);
	
	private OnlineCRLSource cachedSource;
	
	private CRLCacheRepository cacheRepository;

	@Override
	public CRLToken findCrl(final CertificateToken certificateToken) throws DSSException {
		if (certificateToken == null) {
			return null;
		}
		final CertificateToken issuerToken = certificateToken.getIssuerToken();
		if (issuerToken == null) {
			return null;
		}
		final List<String> crlUrls = DSSASN1Utils.getCrlUrls(certificateToken);
		if (Utils.isCollectionEmpty(crlUrls)) {
			return null;
		}
		final String crlUrl = crlUrls.get(0);
		
		LOG.info("CRL's URL for " + certificateToken.getAbbreviation() + " : " + crlUrl);
		
		final String key = DSSUtils.getSHA1Digest(crlUrl);
		final CRLValidity storedValidity = cacheRepository.findCrl(key);
		if (storedValidity != null) {
			if (storedValidity.getNextUpdate().after(new Date())) {
				LOG.debug("CRL in cache");
				final CRLToken crlToken = new CRLToken(certificateToken, storedValidity);
				crlToken.setSourceURL(crlUrl);
				if (crlToken.isValid()) {
					return crlToken;
				}
			}
		}
		final CRLToken crlToken = cachedSource.findCrl(certificateToken);
		if ((crlToken != null) && crlToken.isValid()) {
			if (storedValidity == null) {
				LOG.info("CRL '{}' not in cache", crlUrl);
				cacheRepository.insertCrl(key, crlToken.getCrlValidity());
			} else {
				LOG.debug("CRL '{}' expired", crlUrl);
				cacheRepository.updateCrl(key, crlToken.getCrlValidity());
			}
		}
		return crlToken;
	}

	/**
	 * @param cachedSource
	 *            the cachedSource to set
	 */
	public void setCachedSource(OnlineCRLSource cachedSource) {
		this.cachedSource = cachedSource;
	}

	public void setCacheRepository(CRLCacheRepository cacheRepository) {
		this.cacheRepository = cacheRepository;
	}

}
