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
package eu.europa.esig.dss.client.ocsp;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.client.NonceSource;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationSourceAlternateUrlsSupport;
import eu.europa.esig.dss.x509.ocsp.OCSPRespStatus;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder to retrieve the OCSP response.
 */
@SuppressWarnings("serial")
public class OnlineOCSPSource implements OCSPSource, RevocationSourceAlternateUrlsSupport<OCSPToken> {

	private static final Logger LOG = LoggerFactory.getLogger(OnlineOCSPSource.class);

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * This variable is used to prevent the replay attack.
	 */
	private NonceSource nonceSource;

	/**
	 * The data loader used to retrieve the OCSP response.
	 */
	private DataLoader dataLoader;

	/**
	 * Create an OCSP source The default constructor for OnlineOCSPSource. The default {@code OCSPDataLoader} is set. It
	 * is possible to change it with {@code
	 * #setDataLoader}.
	 */
	public OnlineOCSPSource() {
		dataLoader = new OCSPDataLoader();
	}

	/**
	 * Set the DataLoader to use for querying the OCSP server.
	 *
	 * @param dataLoader
	 *            the component that allows to retrieve the OCSP response using HTTP.
	 */
	public void setDataLoader(final DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	/**
	 * Set the NonceSource to use for querying the OCSP server.
	 *
	 * @param nonceSource
	 *            the component that prevents the replay attack.
	 */
	public void setNonceSource(NonceSource nonceSource) {
		this.nonceSource = nonceSource;
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return getRevocationToken(certificateToken, issuerCertificateToken, Collections.<String>emptyList());
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken, List<String> alternativeUrls) {
		if (dataLoader == null) {
			throw new NullPointerException("DataLoader is not provided !");
		}

		final String dssIdAsString = certificateToken.getDSSIdAsString();
		LOG.trace("--> OnlineOCSPSource queried for {}", dssIdAsString);
		if (Utils.isCollectionNotEmpty(alternativeUrls)) {
			LOG.info("OCSP alternative urls : {}", alternativeUrls);
		}

		final List<String> ocspAccessLocations = DSSASN1Utils.getOCSPAccessLocations(certificateToken);
		if (Utils.isCollectionEmpty(ocspAccessLocations) && Utils.isCollectionEmpty(alternativeUrls)) {
			LOG.debug("No OCSP location found for {}", dssIdAsString);
			return null;
		}
		ocspAccessLocations.addAll(alternativeUrls);

		final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken);

		BigInteger nonce = null;
		if (nonceSource != null) {
			nonce = nonceSource.getNonce();
		}

		final byte[] content = buildOCSPRequest(certId, nonce);

		int nbTries = ocspAccessLocations.size();
		for (String ocspAccessLocation : ocspAccessLocations) {
			nbTries--;
			try {
				final byte[] ocspRespBytes = dataLoader.post(ocspAccessLocation, content);
				if (!Utils.isArrayEmpty(ocspRespBytes)) {
					final OCSPResp ocspResp = new OCSPResp(ocspRespBytes);
					OCSPRespStatus status = OCSPRespStatus.fromInt(ocspResp.getStatus());
					if (OCSPRespStatus.SUCCESSFUL.equals(status)) {
						OCSPToken ocspToken = new OCSPToken();
						ocspToken.setResponseStatus(status);
						ocspToken.setSourceURL(ocspAccessLocation);
						ocspToken.setCertId(certId);
						ocspToken.setAvailable(true);
						final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
						ocspToken.setBasicOCSPResp(basicOCSPResp);

						if (nonceSource != null) {
							ocspToken.setUseNonce(true);
							ocspToken.setNonceMatch(isNonceMatch(basicOCSPResp, nonce));
						}
						return ocspToken;
					} else {
						LOG.warn("OCSP Response status with URL '{}' : {}", ocspAccessLocation, status);
					}
				}
			} catch (Exception e) {
				if (nbTries == 0) {
					throw new DSSException("Unable to retrieve OCSP response", e);
				} else {
					LOG.warn("Unable to retrieve OCSP response with URL '{}' : {}", ocspAccessLocation, e.getMessage());
				}
			}
		}

		return null;
	}

	private byte[] buildOCSPRequest(final CertificateID certId, BigInteger nonce) throws DSSException {
		try {
			final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
			ocspReqBuilder.addRequest(certId);
			/*
			 * The nonce extension is used to bind a request to a response to prevent replay attacks.
			 * RFC 6960 (OCSP) section 4.1.2 such extensions SHOULD NOT be flagged as critical
			 */
			if (nonce != null) {
				DEROctetString encodedNonceValue = new DEROctetString(new DEROctetString(nonce.toByteArray()).getEncoded());
				Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, encodedNonceValue);
				Extensions extensions = new Extensions(extension);
				ocspReqBuilder.setRequestExtensions(extensions);
			}
			final OCSPReq ocspReq = ocspReqBuilder.build();
			final byte[] ocspReqData = ocspReq.getEncoded();
			return ocspReqData;
		} catch (OCSPException | IOException e) {
			throw new DSSException("Cannot build OCSP Request", e);
		}
	}

	private boolean isNonceMatch(final BasicOCSPResp basicOCSPResp, BigInteger expectedNonceValue) {
		Extension extension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		ASN1OctetString extnValue = extension.getExtnValue();
		ASN1Primitive value;
		try {
			value = ASN1Primitive.fromByteArray(extnValue.getOctets());
		} catch (IOException ex) {
			LOG.warn("Invalid encoding of nonce extension value in OCSP response", ex);
			return false;
		}
		if (value instanceof DEROctetString) {
			BigInteger receivedNonce = new BigInteger(((DEROctetString) value).getOctets());
			return expectedNonceValue.equals(receivedNonce);
		} else {
			LOG.warn("Nonce extension value in OCSP response is not an OCTET STRING");
			return false;
		}
	}

}
