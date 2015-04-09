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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.client.NonceSource;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder to retrieve the OCSP response.
 */
public class OnlineOCSPSource implements OCSPSource {

	private static final Logger logger = LoggerFactory.getLogger(OnlineOCSPSource.class);

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
	 * Create an OCSP source The default constructor for OnlineOCSPSource. The default {@code OCSPDataLoader} is set. It is possible to change it with {@code
	 * #setDataLoader}.
	 */
	public OnlineOCSPSource() {
		dataLoader = new OCSPDataLoader();
	}

	/**
	 * Set the DataLoader to use for querying the OCSP server.
	 *
	 * @param dataLoader the component that allows to retrieve the OCSP response using HTTP.
	 */
	public void setDataLoader(final DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	/**
	 * Set the NonceSource to use for querying the OCSP server.
	 *
	 * @param nonceSource the component that prevents the replay attack.
	 */
	public void setNonceSource(NonceSource nonceSource) {
		this.nonceSource = nonceSource;
	}

	@Override
	public OCSPToken getOCSPToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		if (dataLoader == null) {
			throw new NullPointerException("DataLoad is not provided !");
		}

		try {
			final String dssIdAsString = certificateToken.getDSSIdAsString();
			if (logger.isTraceEnabled()) {
				logger.trace("--> OnlineOCSPSource queried for " + dssIdAsString);
			}
			final X509Certificate x509Certificate = certificateToken.getCertificate();
			final String ocspAccessLocation = getAccessLocation(x509Certificate);
			if (StringUtils.isEmpty(ocspAccessLocation)) {
				if (logger.isDebugEnabled()) {
					logger.info("No OCSP location found for " + dssIdAsString);
				}
				certificateToken.extraInfo().infoNoOCSPResponse(ocspAccessLocation);
				return null;
			}

			final X509Certificate issuerX509Certificate = issuerCertificateToken.getCertificate();
			final byte[] content = buildOCSPRequest(x509Certificate, issuerX509Certificate);

			final byte[] ocspRespBytes = dataLoader.post(ocspAccessLocation, content);

			final OCSPResp ocspResp = new OCSPResp(ocspRespBytes);

			final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();

			if (nonceSource !=null) {
				Extension extension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
				DEROctetString derReceivedNonce = (DEROctetString) extension.getExtnValue();
				BigInteger receivedNonce = new BigInteger(derReceivedNonce.getOctets());
				if (!receivedNonce.equals(nonceSource.getNonce())) {
					throw new DSSException("The OCSP request for " + dssIdAsString + " was the victim of replay attack: nonce [sent:" + nonceSource.getNonce() + ", received:" + receivedNonce + "]");
				}
			}

			Date bestUpdate = null;
			SingleResp bestSingleResp = null;
			final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(x509Certificate, issuerX509Certificate);
			for (final SingleResp singleResp : basicOCSPResp.getResponses()) {
				if (DSSRevocationUtils.matches(certId, singleResp)) {
					final Date thisUpdate = singleResp.getThisUpdate();
					if ((bestUpdate == null) || thisUpdate.after(bestUpdate)) {
						bestSingleResp = singleResp;
						bestUpdate = thisUpdate;
					}
				}
			}

			if (bestSingleResp != null) {
				final OCSPToken ocspToken = new OCSPToken(basicOCSPResp, bestSingleResp);
				ocspToken.setSourceURI(ocspAccessLocation);
				certificateToken.setRevocationToken(ocspToken);
				return ocspToken;
			}
		} catch (NullPointerException e) {
			throw new DSSException("OCSPResp is initialised with a null OCSP response... (and there is no nullity check in the OCSPResp implementation)", e);
		} catch (OCSPException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
		return null;
	}

	private byte[] buildOCSPRequest(final X509Certificate x509Certificate, final X509Certificate issuerX509Certificate) throws DSSException {

		try {

			final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(x509Certificate, issuerX509Certificate);
			final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
			ocspReqBuilder.addRequest(certId);

			/*
			 * The nonce extension is used to bind a request to a response to prevent replay attacks.
			 */
			if (nonceSource !=null) {
				Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonceSource.getNonce().toByteArray()));
				Extensions extensions = new Extensions(extension);
				ocspReqBuilder.setRequestExtensions(extensions);
			}

			final OCSPReq ocspReq = ocspReqBuilder.build();
			final byte[] ocspReqData = ocspReq.getEncoded();
			return ocspReqData;
		} catch (OCSPException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Gives back the OCSP URI meta-data found within the given X509 cert.
	 *
	 * @param certificate the X509 cert.
	 * @return the OCSP URI, or <code>null</code> if the extension is not present.
	 * @throws DSSException
	 */
	public String getAccessLocation(final X509Certificate certificate) throws DSSException {

		final ASN1ObjectIdentifier ocspAccessMethod = X509ObjectIdentifiers.ocspAccessMethod;
		final byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
		if (null == authInfoAccessExtensionValue) {
			return null;
		}

		ASN1InputStream ais1 = null;
		ASN1InputStream ais2 = null;
		try {

			final ByteArrayInputStream bais = new ByteArrayInputStream(authInfoAccessExtensionValue);
			ais1 = new ASN1InputStream(bais);
			final DEROctetString oct = (DEROctetString) (ais1.readObject());
			ais2 = new ASN1InputStream(oct.getOctets());
			final AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(ais2.readObject());

			final AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
			for (AccessDescription accessDescription : accessDescriptions) {

				if (logger.isDebugEnabled()) {
					logger.debug("Access method: " + accessDescription.getAccessMethod());
				}
				final boolean correctAccessMethod = accessDescription.getAccessMethod().equals(ocspAccessMethod);
				if (!correctAccessMethod) {

					continue;
				}
				final GeneralName gn = accessDescription.getAccessLocation();
				if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {

					if (logger.isDebugEnabled()) {
						logger.debug("Not a uniform resource identifier");
					}
					continue;
				}
				final DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
				final String accessLocation = str.getString();
				if (logger.isDebugEnabled()) {
					logger.debug("Access location: " + accessLocation);
				}
				return accessLocation;
			}
			return null;
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {
			IOUtils.closeQuietly(ais1);
			IOUtils.closeQuietly(ais2);
		}
	}
}
