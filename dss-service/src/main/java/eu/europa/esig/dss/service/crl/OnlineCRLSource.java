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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
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
public class OnlineCRLSource implements CRLSource, RevocationSourceAlternateUrlsSupport<CRL> {
	
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
	 * when retrieving the CRL to choose the canal.<br>
	 * Possible values are: http, ldap, ftp
	 *
	 * @param preferredProtocol
	 *            {@code Protocol} that is used first to retrieve the revocation
	 *            data
	 */
	public void setPreferredProtocol(final Protocol preferredProtocol) {
		this.preferredProtocol = preferredProtocol;
	}

	/**
	 * Set the DataLoader to use for querying a revocation server.
	 *
	 * @param dataLoader
	 *            the component that allows to retrieve a CRL response using HTTP.
	 */
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
		Objects.requireNonNull(certificateToken, "CertificateToken cannot be null!");
		Objects.requireNonNull(issuerToken, "Issuer CertificateToken cannot be null!");
		Objects.requireNonNull(dataLoader, "DataLoader is not provided !");
		LOG.trace("--> OnlineCRLSource queried for {}", certificateToken.getDSSIdAsString());

		final List<String> crlUrls = getCRLAccessURLs(certificateToken, alternativeUrls);
		if (Utils.isCollectionEmpty(crlUrls)) {
			throw new DSSExternalResourceException(String.format(
					"No CRL location found for certificate with Id '%s'", certificateToken.getDSSIdAsString()));
		}

		int nbTries = crlUrls.size();
		for (String crlUrl : crlUrls) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Trying to retrieve a CRL from URL '{}'...", crlUrl);
			}
			nbTries--;

			try {
				final CRLBinary crlBinary = executeCRLRequest(crlUrl);
				final CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, issuerToken);
				final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
				crlToken.setExternalOrigin(RevocationOrigin.EXTERNAL);
				crlToken.setSourceURL(crlUrl);
				if (LOG.isDebugEnabled()) {
					LOG.debug("CRL '{}' has been retrieved from a source with URL '{}'.",
							crlToken.getDSSIdAsString(), crlUrl);
				}
				return crlToken;

			} catch (Exception e) {
				if (nbTries == 0) {
					throw new DSSExternalResourceException(String.format(
							"Unable to retrieve CRL for certificate with Id '%s' from URL '%s'. Reason : %s",
							certificateToken.getDSSIdAsString(), crlUrl, e.getMessage()), e);
				} else {
					LOG.warn("Unable to retrieve CRL with URL '{}' : {}", crlUrl, e.getMessage());
				}
			}

		}

		throw new IllegalStateException(String.format("Invalid state within OnlineCRLSource " +
				"for a certificate call with id '%s'", certificateToken.getDSSIdAsString()));
	}

	/**
	 * Extracts a list of CRL distribution point URLs to be used in the provided order to retrieve a CRL
	 *
	 * @param certificateToken {@link CertificateToken} to retrieve CRL for
	 * @param alternativeUrls a list of {@link String} representing alternative URL sources
	 * @return a list of {@link String} urls
	 */
	protected List<String> getCRLAccessURLs(CertificateToken certificateToken, List<String> alternativeUrls) {
		if (Utils.isCollectionNotEmpty(alternativeUrls)) {
			LOG.info("CRL alternative urls : {}", alternativeUrls);
		}

		final List<String> crlAccessUrls = CertificateExtensionsUtils.getCRLAccessUrls(certificateToken);

		final List<String> crlUrls = new ArrayList<>();
		crlUrls.addAll(crlAccessUrls);
		crlUrls.addAll(alternativeUrls);

		prioritize(crlUrls);
		return crlUrls;
	}

	/**
	 * This method retrieves a {@code RevocationTokenAndUrl} for the certificateToken
	 *
	 * @param certificateToken
	 *                               The {@code CertificateToken} for which the
	 *                               request is made
	 * @param issuerToken
	 *                               The {@code CertificateToken} which is the
	 *                               issuer of the certificateToken
	 * @return an instance of {@code RevocationTokenAndUrl}
	 * @deprecated since DSS 5.13. Use {@code #getRevocationToken(certificateToken, issuerToken).getSourceURL()} method
	 */
	@Deprecated
	public OnlineRevocationSource.RevocationTokenAndUrl<CRL> getRevocationTokenAndUrl(CertificateToken certificateToken, CertificateToken issuerToken) {
		CRLToken revocationToken = getRevocationToken(certificateToken, issuerToken);
		if (revocationToken != null) {
			return new OnlineRevocationSource.RevocationTokenAndUrl<>(revocationToken.getSourceURL(), revocationToken);
		}
		return null;
	}

	/**
	 * Extracts a CRL token for a {@code certificateToken} from the given list of {@code crlUrls}
	 *
	 * @param certificateToken {@link CertificateToken} to get a CRL token for
	 * @param issuerToken {@link CertificateToken} issued the {@code certificateToken}
	 * @param crlUrls a list of {@link String} URLs to use to access a CRL token
	 * @return {@link OnlineRevocationSource.RevocationTokenAndUrl}
	 * @deprecated since DSS 5.13. Use {@code #getRevocationToken(certificateToken, issuerToken,crlUrls).getSourceURL()} method
	 */
	@Deprecated
	protected OnlineRevocationSource.RevocationTokenAndUrl<CRL> getRevocationTokenAndUrl(CertificateToken certificateToken,
																  CertificateToken issuerToken, List<String> crlUrls) {
		CRLToken revocationToken = getRevocationToken(certificateToken, issuerToken, crlUrls);
		if (revocationToken != null) {
			return new OnlineRevocationSource.RevocationTokenAndUrl<>(revocationToken.getSourceURL(), revocationToken);
		}
		return null;
	}

	/**
	 * Download a CRL from given location
	 *
	 * @param crlUrl {@link String} url to download CRL from
	 * @return {@link CRLBinary}
	 */
	protected CRLBinary executeCRLRequest(final String crlUrl) {
		byte[] bytes = dataLoader.get(crlUrl);
		if (Utils.isArrayNotEmpty(bytes)) {
			return CRLUtils.buildCRLBinary(bytes);
		}
		throw new DSSExternalResourceException(String.format("CRL DataLoader for certificate with url '%s' " +
				"responded with an empty byte array!", crlUrl));
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
