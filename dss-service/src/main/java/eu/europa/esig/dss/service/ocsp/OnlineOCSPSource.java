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
package eu.europa.esig.dss.service.ocsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.NonceSource;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.revocation.OnlineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSourceAlternateUrlsSupport;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
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
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder
 * to retrieve the OCSP response.
 */
@SuppressWarnings("serial")
public class OnlineOCSPSource implements OCSPSource, RevocationSourceAlternateUrlsSupport<OCSP>, OnlineRevocationSource<OCSP> {

	private static final Logger LOG = LoggerFactory.getLogger(OnlineOCSPSource.class);

	/**
	 * This variable is used to prevent the replay attack.
	 */
	private NonceSource nonceSource;

	/**
	 * The data loader used to retrieve the OCSP response.
	 */
	private DataLoader dataLoader;
	
	/**
	 * The DigestAlgorithm to be used in hash calculation for CertID on a request building
	 */
	private DigestAlgorithm certIDDigestAlgorithm = DigestAlgorithm.SHA1;
	
	/**
	 * A collection of DigestAlgorithms to exclude OCSPTokens signed by them
	 */
	private Collection<DigestAlgorithm> digestAlgorithmsForExclusion = Arrays.asList(DigestAlgorithm.MD2, DigestAlgorithm.MD5, 
			DigestAlgorithm.RIPEMD160, DigestAlgorithm.SHA1, DigestAlgorithm.WHIRLPOOL);

	/**
	 * Create an OCSP source The default constructor for OnlineOCSPSource. The
	 * default {@code OCSPDataLoader} is set. It is possible to change it with
	 * {@code #setDataLoader(dataLoader)}.
	 */
	public OnlineOCSPSource() {
		dataLoader = new OCSPDataLoader();
		LOG.trace("+OnlineOCSPSource with the default data loader.");
	}
	
	/**
	 * Creates an Online OCSP Source with the provided {@code DataLoader} instance.
	 * It is still possible to change the defined instance with 
	 * {@code #setDataLoader(dataLoader)}.
	 * 
	 * @param dataLoader {@link DataLoader} to use
	 */
	public OnlineOCSPSource(final DataLoader dataLoader) {
		this.dataLoader = dataLoader;
		LOG.trace("+OnlineOCSPSource with the specific data loader.");
	}

	@Override
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
	
	/**
	 * This method allows setting of DigestAlgorithm to be used in hash calculation
	 * for CertID element in an OCSP request building
	 * 
	 * @param certIDDigestAlgorithm {@link DigestAlgorithm}
	 */
	public void setCertIDDigestAlgorithm(DigestAlgorithm certIDDigestAlgorithm) {
		Objects.requireNonNull(certIDDigestAlgorithm, "The certIDDigestAlgorithm must not be null!");
		this.certIDDigestAlgorithm = certIDDigestAlgorithm;
	}

	/**
	 * Sets a collection of DigestAlgorithms for exclusion
	 * If an OCSPToken is signed with a listed algorithm, the OCSPToken will be skipped
	 * 
	 * @param digestAlgorithmsForExclusion an array if {@link DigestAlgorithm}s
	 */
	public void setDigestAlgorithmsForExclusion(Collection<DigestAlgorithm> digestAlgorithmsForExclusion) {
		Objects.requireNonNull(digestAlgorithmsForExclusion, "The collection of DigestAlgorithms for exclusion cannot be null!");
		this.digestAlgorithmsForExclusion = digestAlgorithmsForExclusion;
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return getRevocationToken(certificateToken, issuerCertificateToken, Collections.emptyList());
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken,
			List<String> alternativeUrls) {
		Objects.requireNonNull(dataLoader, "DataLoader is not provided !");

		final String dssIdAsString = certificateToken.getDSSIdAsString();
		LOG.trace("--> OnlineOCSPSource queried for {}", dssIdAsString);
		if (Utils.isCollectionNotEmpty(alternativeUrls)) {
			LOG.info("OCSP alternative urls : {}", alternativeUrls);
		}

		final List<String> ocspAccessLocations = DSSASN1Utils.getOCSPAccessLocations(certificateToken);
		if (Utils.isCollectionEmpty(ocspAccessLocations) && Utils.isCollectionEmpty(alternativeUrls)) {
			LOG.warn("No OCSP location found for {}", dssIdAsString);
			return null;
		}
		ocspAccessLocations.addAll(alternativeUrls);

		RevocationTokenAndUrl<OCSP> revocationTokenAndUrl = getRevocationTokenAndUrl(certificateToken, issuerCertificateToken, ocspAccessLocations);
		if (revocationTokenAndUrl != null) {
			return (OCSPToken) revocationTokenAndUrl.getRevocationToken();
		} else {
			LOG.debug("No OCSP has been downloaded for a CertificateToken with Id '{}' from a list of urls : {}",
					certificateToken.getDSSIdAsString(), ocspAccessLocations);
			return null;
		}
	}

	@Override
	public RevocationTokenAndUrl<OCSP> getRevocationTokenAndUrl(CertificateToken certificateToken,
																CertificateToken issuerToken) {
		final List<String> ocspAccessLocations = DSSASN1Utils.getOCSPAccessLocations(certificateToken);
		if (Utils.isCollectionEmpty(ocspAccessLocations)) {
			LOG.warn("No OCSP location found for {}", certificateToken.getDSSIdAsString());
			return null;
		}
		return getRevocationTokenAndUrl(certificateToken, issuerToken, ocspAccessLocations);
	}

	/**
	 * Extracts an OCSP token for a {@code certificateToken} from the given list of {@code ocspUrls}
	 *
	 * @param certificateToken {@link CertificateToken} to get an OCSP token for
	 * @param issuerToken {@link CertificateToken} issued the {@code certificateToken}
	 * @param ocspUrls a list of {@link String} URLs to use to access an OCSP token
	 * @return {@link RevocationTokenAndUrl}
	 */
	protected RevocationTokenAndUrl<OCSP> getRevocationTokenAndUrl(CertificateToken certificateToken,
																   CertificateToken issuerToken, List<String> ocspUrls) {
		final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerToken, certIDDigestAlgorithm);

		BigInteger nonce = null;
		if (nonceSource != null) {
			nonce = nonceSource.getNonce();
		}

		final byte[] content = buildOCSPRequest(certId, nonce);

		int nbTries = ocspUrls.size();
		for (String ocspAccessLocation : ocspUrls) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Trying to retrieve an OCSP response from URL '{}'...", ocspAccessLocation);
			}
			nbTries--;

			try {
				final byte[] ocspRespBytes = dataLoader.post(ocspAccessLocation, content);
				if (!Utils.isArrayEmpty(ocspRespBytes)) {
					if (LOG.isTraceEnabled()) {
						LOG.trace(String.format("Obtained OCSPResponse binaries from URL '%s' : %s", ocspAccessLocation, Utils.toBase64(ocspRespBytes)));
					}
					final OCSPResp ocspResp = new OCSPResp(ocspRespBytes);
					verifyNonce(ocspResp, nonce);

					OCSPRespStatus status = OCSPRespStatus.fromInt(ocspResp.getStatus());
					if (OCSPRespStatus.SUCCESSFUL.equals(status)) {
						BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
						SingleResp latestSingleResponse = DSSRevocationUtils.getLatestSingleResponse(basicResponse, certificateToken, issuerToken);
						OCSPToken ocspToken = new OCSPToken(basicResponse, latestSingleResponse, certificateToken, issuerToken);
						ocspToken.setSourceURL(ocspAccessLocation);
						ocspToken.setExternalOrigin(RevocationOrigin.EXTERNAL);
						if (isAcceptableDigestAlgo(ocspToken.getSignatureAlgorithm())) {
							if (LOG.isDebugEnabled()) {
								LOG.debug("OCSP Response '{}' has been retrieved from a source with URL '{}'.",
										ocspToken.getDSSIdAsString(), ocspAccessLocation);
							}
							return new RevocationTokenAndUrl<>(ocspAccessLocation, ocspToken);

						} else {
							LOG.warn("The SignatureAlgorithm '{}' of the obtained OCSPToken from URL '{}' is not acceptable! "
									+ "The OCSPToken is skipped.", ocspToken.getSignatureAlgorithm(), ocspAccessLocation);
						}

					} else {
						LOG.warn("Ignored OCSP Response from URL '{}' : status -> {}", ocspAccessLocation, status);
					}

				} else {
					LOG.warn("OCSP Data Loader for certificate {} responded with an empty byte array!", certificateToken.getDSSIdAsString());
				}

			} catch (Exception e) {
				if (nbTries == 0) {
					throw new DSSExternalResourceException(String.format(
							"Unable to retrieve OCSP response for certificate with Id '%s' from URL '%s'. Reason : %s",
							certificateToken.getDSSIdAsString(), ocspAccessLocation, e.getMessage()), e);
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
			 * The nonce extension is used to bind a request to a response to
			 * prevent replay attacks. RFC 6960 (OCSP) section 4.1.2 such
			 * extensions SHOULD NOT be flagged as critical
			 */
			if (nonce != null) {
				DEROctetString encodedNonceValue = new DEROctetString(
						new DEROctetString(nonce.toByteArray()).getEncoded());
				Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, encodedNonceValue);
				Extensions extensions = new Extensions(extension);
				ocspReqBuilder.setRequestExtensions(extensions);
			}
			final OCSPReq ocspReq = ocspReqBuilder.build();
			return ocspReq.getEncoded();

		} catch (OCSPException | IOException e) {
			throw new DSSException("Cannot build OCSP Request", e);
		}
	}
	
	private void verifyNonce(final OCSPResp ocspResp, final BigInteger expectedNonceValue) {
		if (expectedNonceValue != null) {
			BigInteger receivedNonce = getEmbeddedNonceValue(ocspResp);
			if (!expectedNonceValue.equals(receivedNonce)) {
				throw new DSSExternalResourceException(String.format("Nonce received from OCSP response '%s' " +
								"does not match a dispatched nonce '%s'.", receivedNonce, expectedNonceValue));
			}
		}
	}
	
	private BigInteger getEmbeddedNonceValue(final OCSPResp ocspResp) {
		try {
			BasicOCSPResp basicOCSPResp = (BasicOCSPResp)ocspResp.getResponseObject();
			
			Extension extension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
			ASN1OctetString extnValue = extension.getExtnValue();
			ASN1Primitive value = fromByteArray(extnValue);
			if (value instanceof DEROctetString) {
				return new BigInteger(((DEROctetString) value).getOctets());
			}
			throw new OCSPException("Nonce extension value in OCSP response is not an OCTET STRING");

		} catch (Exception e) {
			throw new DSSExternalResourceException(String.format("Unable to extract the nonce from the OCSPResponse! " +
					"Reason : [%s]", e.getMessage()), e);
		}
	}

	private ASN1Primitive fromByteArray(ASN1OctetString extnValue) throws OCSPException {
		try {
			return ASN1Primitive.fromByteArray(extnValue.getOctets());
		} catch (IOException ex) {
			throw new OCSPException("Invalid encoding of nonce extension value in OCSP response", ex);
		}
	}
	
	private boolean isAcceptableDigestAlgo(SignatureAlgorithm signatureAlgorithm) {
		return signatureAlgorithm != null && !digestAlgorithmsForExclusion.contains(signatureAlgorithm.getDigestAlgorithm());
	}

}
