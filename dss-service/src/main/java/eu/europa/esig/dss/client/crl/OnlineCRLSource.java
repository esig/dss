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
package eu.europa.esig.dss.client.crl;

import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.Protocol;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.crl.CRLUtils;
import eu.europa.esig.dss.x509.crl.CRLValidity;

/**
 * Online CRL repository. This CRL repository implementation will download the CRLs from the given CRL URIs.
 * Note that for the HTTP kind of URLs you can provide dedicated data loader. If the data loader is not provided the standard load from URI is
 * provided. For FTP the standard load from URI is provided. For LDAP kind of URLs an internal implementation using apache-ldap-api is provided.
 *
 *
 */

public class OnlineCRLSource implements CRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(OnlineCRLSource.class);

	/**
	 * If the multiple protocols are available to retrieve the revocation data, then that indicated by this variable is used first.
	 */
	private Protocol preferredProtocol;

	/**
	 * The component that allows to retrieve the data using any protocol: HTTP, HTTPS, FTP, LDAP.
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
	 * @param dataLoader the component that allows to retrieve the data using any protocol: HTTP, HTTPS, FTP, LDAP.
	 */
	public OnlineCRLSource(final DataLoader dataLoader) {

		this.dataLoader = dataLoader;
		LOG.trace("+OnlineCRLSource with the specific data loader.");
	}

	/**
	 * This method allows to set the preferred protocol. This parameter is used used when retrieving the CRL to choose the canal.<br/>
	 * Possible values are: http, ldap, ftp
	 *
	 * @param preferredProtocol {@code Protocol} that is used first to retrieve the revocation data
	 */
	public void setPreferredProtocol(final Protocol preferredProtocol) {

		this.preferredProtocol = preferredProtocol;
	}

	/**
	 * Set the DataLoader to use for querying the CRL server
	 *
	 * @param dataLoader the component that allows to retrieve the data using any protocol: HTTP, HTTPS, FTP, LDAP.
	 */
	public void setDataLoader(final DataLoader dataLoader) {

		this.dataLoader = dataLoader;
	}

	@Override
	public CRLToken findCrl(final CertificateToken certificateToken) throws DSSException {

		if (certificateToken == null) {
			return null;
		}
		final CertificateToken issuerToken = certificateToken.getIssuerToken();
		if (issuerToken == null) {
			return null;
		}
		final List<String> crlUrls = getCrlUrl(certificateToken);
		LOG.info("CRL's URL for " + certificateToken.getAbbreviation() + " : " + crlUrls);
		if (CollectionUtils.isEmpty(crlUrls)) {
			return null;
		}
		final DataLoader.DataAndUrl dataAndUrl = downloadCrl(crlUrls);
		if (dataAndUrl == null) {
			return null;
		}
		final X509CRL crl;
		try {
			crl = DSSUtils.loadCRL(dataAndUrl.data);
		} catch (Exception e) {
			LOG.warn("", e);
			return null;
		}
		final CRLValidity crlValidity = CRLUtils.isValidCRL(crl, issuerToken);
		final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
		crlToken.setSourceURL(dataAndUrl.urlString);
		return crlToken;
	}

	/**
	 * Download a CRL from any location with any protocol.
	 *
	 * @param downloadUrls the {@code List} of urls to be used to obtain the revocation data through the CRL canal.
	 * @return {@code X509CRL} or null if it was not possible to download the CRL
	 */
	private DataLoader.DataAndUrl downloadCrl(final List<String> downloadUrls) {

		if (CollectionUtils.isEmpty(downloadUrls)) {
			return null;
		}
		try {

			final DataLoader.DataAndUrl dataAndUrl = dataLoader.get(downloadUrls);
			return dataAndUrl;
		} catch (DSSException e) {
			LOG.warn("", e);
		}
		return null;
	}

	/**
	 * Gives back the {@code List} of CRL URI meta-data found within the given X509 certificate.
	 *
	 * @param certificateToken the X509 certificate
	 * @return the {@code List} of CRL URI, or {@code null} if the extension is not present
	 * @throws DSSException
	 */
	public List<String> getCrlUrl(final CertificateToken certificateToken) throws DSSException {

		final byte[] crlDistributionPointsBytes = certificateToken.getCRLDistributionPoints();
		if (null == crlDistributionPointsBytes) {

			return null;
		}
		try {

			final List<String> urls = new ArrayList<String>();
			final ASN1Sequence asn1Sequence = DSSASN1Utils.getAsn1SequenceFromDerOctetString(crlDistributionPointsBytes);
			final CRLDistPoint distPoint = CRLDistPoint.getInstance(asn1Sequence);
			final DistributionPoint[] distributionPoints = distPoint.getDistributionPoints();
			for (final DistributionPoint distributionPoint : distributionPoints) {

				final DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
				if (DistributionPointName.FULL_NAME != distributionPointName.getType()) {
					continue;
				}
				final GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
				final GeneralName[] names = generalNames.getNames();
				for (final GeneralName name : names) {

					if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {

						LOG.debug("Not a uniform resource identifier");
						continue;
					}
					ASN1Primitive asn1Primitive = name.toASN1Primitive();
					if (asn1Primitive instanceof DERTaggedObject) {

						final DERTaggedObject taggedObject = (DERTaggedObject) asn1Primitive;
						asn1Primitive = taggedObject.getObject();
					}
					final DERIA5String derStr = DERIA5String.getInstance(asn1Primitive);
					final String urlStr = derStr.getString();
					urls.add(urlStr);
				}
			}
			prioritize(urls);
			return urls;
		} catch (Exception e) {
			if (e instanceof DSSException) {
				throw (DSSException) e;
			}
			throw new DSSException(e);
		}
	}

	/**
	 * if {@code preferredProtocol} is set then the list of urls is prioritize.
	 * NOTE: This is not standard conformant! However in the major number of cases LDAP is much slower then HTTP!
	 *
	 * @param urls {@code List} of urls to prioritize
	 */
	private void prioritize(final List<String> urls) {

		if (preferredProtocol != null) {

			final List<String> priorityUrls = new ArrayList<String>();
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
