/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.service.crl;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.x509.revocation.OnlineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSourceAlternateUrlsSupport;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Online CRL repository. This CRL repository implementation will download the
 * CRLs from the given CRL URIs. Note that for the HTTP kind of URLs you can
 * provide dedicated data loader. If the data loader is not provided the
 * standard load from URI is provided. For FTP the standard load from URI is
 * provided. For LDAP kind of URLs an internal implementation using
 * apache-ldap-api is provided.
 *
 */
public class OnlineCRLSource implements CRLSource, RevocationSourceAlternateUrlsSupport<CRL>, OnlineRevocationSource<CRL> {
	
	private static final long serialVersionUID = 6912729291417315212L;

	private static final Logger LOG = LoggerFactory.getLogger(OnlineCRLSource.class);

	/**
	 * If the multiple protocols are available to retrieve the revocation data,
	 * then that indicated by this variable is used first.
	 */
	private Protocol preferredProtocol;

	/**
	 * The component that allows to retrieve the data using any protocol: HTTP,
	 * HTTPS, FTP, LDAP.
	 */
	private DataLoader dataLoader;

	/**
	 * The default constructor. A {@code CommonsDataLoader is created}.
	 */
	public OnlineCRLSource() {
		dataLoader = new CommonsDataLoader();
		LOG.trace("+OnlineCRLSource with the default data loader.");
	}

	/**
	 * This constructor allows to set a specific {@code DataLoader}.
	 *
	 * @param dataLoader
	 *            the component that allows to retrieve the data using any
	 *            protocol: HTTP, HTTPS, FTP, LDAP.
	 */
	public OnlineCRLSource(final DataLoader dataLoader) {
		this.dataLoader = dataLoader;
		LOG.trace("+OnlineCRLSource with the specific data loader.");
	}

	/**
	 * This method allows to set the preferred protocol. This parameter is used
	 * used when retrieving the CRL to choose the canal.<br>
	 * Possible values are: http, ldap, ftp
	 *
	 * @param preferredProtocol
	 *            {@code Protocol} that is used first to retrieve the revocation
	 *            data
	 */
	public void setPreferredProtocol(final Protocol preferredProtocol) {
		this.preferredProtocol = preferredProtocol;
	}

	@Override
	public void setDataLoader(final DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	@Override
	public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return getRevocationToken(certificateToken, issuerCertificateToken, Collections.emptyList());
	}

	@Override
	public CRLToken getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerToken,
			List<String> alternativeUrls) {
		Objects.requireNonNull(dataLoader, "DataLoader is not provided !");

		if (certificateToken == null) {
			return null;
		}

		if (Utils.isCollectionNotEmpty(alternativeUrls)) {
			LOG.info("CRL alternative urls : {}", alternativeUrls);
		}

		final List<String> crlUrls = CertificateExtensionsUtils.getCRLAccessUrls(certificateToken);
		if (Utils.isCollectionEmpty(crlUrls) && Utils.isCollectionEmpty(alternativeUrls)) {
			LOG.debug("No CRL location found for {}", certificateToken.getDSSIdAsString());
			return null;
		}
		crlUrls.addAll(alternativeUrls);

		RevocationTokenAndUrl<CRL> revocationTokenAndUrl = getRevocationTokenAndUrl(certificateToken, issuerToken, crlUrls);
		if (revocationTokenAndUrl != null) {
			return (CRLToken) revocationTokenAndUrl.getRevocationToken();
		} else {
			LOG.debug("No CRL has been downloaded for a CertificateToken with Id '{}' from a list of urls : {}",
					certificateToken.getDSSIdAsString(), crlUrls);
			return null;
		}
	}

	@Override
	public RevocationTokenAndUrl<CRL> getRevocationTokenAndUrl(CertificateToken certificateToken, CertificateToken issuerToken) {
		Objects.requireNonNull(dataLoader, "DataLoader is not provided !");

		if (certificateToken == null) {
			return null;
		}

		final List<String> crlUrls = CertificateExtensionsUtils.getCRLAccessUrls(certificateToken);
		if (Utils.isCollectionEmpty(crlUrls)) {
			LOG.debug("No CRL location found for {}", certificateToken.getDSSIdAsString());
			return null;
		}

		return getRevocationTokenAndUrl(certificateToken, issuerToken, crlUrls);
	}

	/**
	 * Extracts a CRL token for a {@code certificateToken} from the given list of {@code crlUrls}
	 *
	 * @param certificateToken {@link CertificateToken} to get a CRL token for
	 * @param issuerToken {@link CertificateToken} issued the {@code certificateToken}
	 * @param crlUrls a list of {@link String} URLs to use to access a CRL token
	 * @return {@link RevocationTokenAndUrl}
	 */
	protected RevocationTokenAndUrl<CRL> getRevocationTokenAndUrl(CertificateToken certificateToken,
																  CertificateToken issuerToken, List<String> crlUrls) {
		Objects.requireNonNull(dataLoader, "DataLoader is not provided !");
		if (issuerToken == null) {
			return null;
		}
		if (Utils.isCollectionEmpty(crlUrls)) {
			return null;
		}
		prioritize(crlUrls);

		if (LOG.isDebugEnabled()) {
			LOG.debug("Trying to retrieve a CRL from URL(s) {}...", crlUrls);
		}
		final DataLoader.DataAndUrl dataAndUrl = downloadCrl(crlUrls);
		if (dataAndUrl == null) {
			return null;
		}
		try {
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(dataAndUrl.getData());
			final CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, issuerToken);
			final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
			crlToken.setExternalOrigin(RevocationOrigin.EXTERNAL);
			crlToken.setSourceURL(dataAndUrl.getUrlString());
			if (LOG.isDebugEnabled()) {
				LOG.debug("CRL '{}' has been retrieved from a source with URL '{}'.",
						crlToken.getDSSIdAsString(), dataAndUrl.getUrlString());
			}
			return new RevocationTokenAndUrl<>(dataAndUrl.getUrlString(), crlToken);

		} catch (Exception e) {
			LOG.warn("Unable to parse/validate the CRL (url: {}) : {}", dataAndUrl.getUrlString(), e.getMessage(), e);
			return null;
		}
	}

	/**
	 * Download a CRL from any location with any protocol.
	 *
	 * @param downloadUrls
	 *            the {@code List} of urls to be used to obtain the revocation
	 *            data through the CRL canal.
	 * @return {@code X509CRL} or null if it was not possible to download the
	 *         CRL
	 */
	private DataLoader.DataAndUrl downloadCrl(final List<String> downloadUrls) {
		try {
			return dataLoader.get(downloadUrls);
		} catch (DSSException e) {
			LOG.warn("Unable to download CRL from URLs [{}]. Reason : [{}]", downloadUrls, e.getMessage(), e);
			return null;
		}
	}

	/**
	 * if {@code preferredProtocol} is set then the list of urls is prioritize.
	 * NOTE: This is not standard conformant! However in the major number of
	 * cases LDAP is much slower then HTTP!
	 *
	 * @param urls
	 *            {@code List} of urls to prioritize
	 */
	private void prioritize(final List<String> urls) {

		if (preferredProtocol != null) {

			final List<String> priorityUrls = new ArrayList<>();
			for (final String url : urls) {
				if (preferredProtocol.isTheSame(url)) {
					priorityUrls.add(url);
				}
			}
			urls.removeAll(priorityUrls);
			for (int ii = priorityUrls.size() - 1; ii >= 0; ii--) {
				urls.add(0, priorityUrls.get(ii));
			}
		}
	}

}
