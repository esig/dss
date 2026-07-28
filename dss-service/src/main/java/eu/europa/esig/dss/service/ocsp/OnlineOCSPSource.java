/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.service.ocsp;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.alert.status.MessageStatus;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.NonceSource;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
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
import org.slf4j.event.Level;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder
 * to retrieve the OCSP response.
 */
@SuppressWarnings("serial")
public class OnlineOCSPSource implements OCSPSource, RevocationSourceAlternateUrlsSupport<OCSP> {

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
	 * This variable sets a behavior when an obtained OCSP response's nonce does not match the expected value.
	 * NOTE: applies only when {@code nonceSource} is defined.
	 */
	private StatusAlert alertOnInvalidNonce = new ExceptionOnStatusAlert();

	/**
	 * This variable sets a behavior when an obtained OCSP response does not contain expected nonce value.
	 * NOTE: applies only when {@code nonceSource} is defined.
	 */
	private StatusAlert alertOnNonexistentNonce = new LogOnStatusAlert(Level.WARN);

	/**
	 * This variable sets a behavior when the current time is not within the range extracted from
	 * thisUpdate and nextUpdate fields of the obtained OCSP response.
	 * NOTE: applies only when nonce validation is not performed.
	 */
	private StatusAlert alertOnInvalidUpdateTime = new SilentOnStatusAlert();

	/**
	 * Clients MAY allow configuration of a small tolerance period for acceptance of responses after
	 * nextUpdate to handle minor clock differences relative to responders and caches.
	 */
	private long nextUpdateTolerancePeriod = 0;

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

	/**
	 * Set the DataLoader to use for querying a revocation server.
	 *
	 * @param dataLoader
	 *            the component that allows to retrieve an OCSP response using HTTP.
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
	 * Sets a behavior when the nonce of the OCSP Response does not match the nonce sent within the request
	 * Default : ExceptionOnStatusAlert (throws an exception if nonce does not match)
	 *
	 * @param alertOnInvalidNonce {@link StatusAlert}
	 */
	public void setAlertOnInvalidNonce(StatusAlert alertOnInvalidNonce) {
		this.alertOnInvalidNonce = alertOnInvalidNonce;
	}

	/**
	 * Sets a behavior when the obtained OCSP Response does not contain the nonce even that the nonce has been enforced
	 * (i.e. {@code nonceSource} is specified).
	 * Default : LogOnStatusAlert (logs a warning in case the OCSP Response does not contain the nonce)
	 *
	 * @param alertOnNonexistentNonce {@link StatusAlert}
	 */
	public void setAlertOnNonexistentNonce(StatusAlert alertOnNonexistentNonce) {
		this.alertOnNonexistentNonce = alertOnNonexistentNonce;
	}

	/**
	 * Sets a behavior when the current time is out of the range of thisUpdate and nextUpdate fields extracted 
	 * from the OCSP Response. The check is executed only when nonce is not checked.
	 * Default : SilentOnStatusAlert (skips the check validation)
	 * 
	 * @param alertOnInvalidUpdateTime {@link StatusAlert}
	 */
	public void setAlertOnInvalidUpdateTime(StatusAlert alertOnInvalidUpdateTime) {
		this.alertOnInvalidUpdateTime = alertOnInvalidUpdateTime;
	}

	/**
	 * Clients MAY allow configuration of a small tolerance period for acceptance of responses after
	 * nextUpdate to handle minor clock differences relative to responders and caches.
	 * I.e. currentTime shall not be after nextUpdate + nextUpdateTolerancePeriod.
	 * The setting is applicable only when {@code checkOCSPResponseUpdateTime} is enabled and no nonce is checked.
	 * Default : 0
	 *
	 * @param nextUpdateTolerancePeriod the tolerance period in milliseconds
	 */
	public void setNextUpdateTolerancePeriod(long nextUpdateTolerancePeriod) {
		this.nextUpdateTolerancePeriod = nextUpdateTolerancePeriod;
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return getRevocationToken(certificateToken, issuerCertificateToken, Collections.emptyList());
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken,
										List<String> alternativeUrls) {
		Objects.requireNonNull(certificateToken, "CertificateToken cannot be null!");
		Objects.requireNonNull(issuerCertificateToken, "Issuer CertificateToken cannot be null!");
		Objects.requireNonNull(dataLoader, "DataLoader is not provided !");
		LOG.trace("--> OnlineOCSPSource queried for {}", certificateToken.getDSSIdAsString());

		final List<String> ocspUrls = getOCSPAccessURLs(certificateToken, alternativeUrls);
		if (Utils.isCollectionEmpty(ocspUrls)) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("No OCSP location found for certificate with Id '{}'", certificateToken.getDSSIdAsString());
			}
			// Return NULL, please see DSS-3601, DSS-3607
			return null;
		}

		byte[] nonce = null;
		if (nonceSource != null) {
			nonce = nonceSource.getNonceValue();
		}

		final byte[] content = buildOCSPRequest(certificateToken, issuerCertificateToken, nonce);

		int nbTries = ocspUrls.size();
		for (String ocspAccessLocation : ocspUrls) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Trying to retrieve an OCSP response from URL '{}'...", ocspAccessLocation);
			}
			nbTries--;

			try {
				BasicOCSPResp basicResponse = executeOCSPRequest(ocspAccessLocation, content);
				SingleResp latestSingleResponse = DSSRevocationUtils.getLatestSingleResponse(basicResponse, certificateToken, issuerCertificateToken);
				assertOCSPResponseValid(basicResponse, latestSingleResponse, nonce);

				OCSPToken ocspToken = new OCSPToken(basicResponse, latestSingleResponse, certificateToken, issuerCertificateToken);
				ocspToken.setSourceURL(ocspAccessLocation);
				ocspToken.setExternalOrigin(RevocationOrigin.EXTERNAL);

				if (LOG.isDebugEnabled()) {
					LOG.debug("OCSP Response '{}' has been retrieved from a source with URL '{}'.",
							ocspToken.getDSSIdAsString(), ocspAccessLocation);
				}
				return ocspToken;

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

		throw new IllegalStateException(String.format("Invalid state within OnlineOCSPSource " +
				"for a certificate call with id '%s'", certificateToken.getDSSIdAsString()));
	}

	/**
	 * Extracts a list of OCSP access URLs to be used in the provided order to retrieve an OCSP response
	 *
	 * @param certificateToken {@link CertificateToken} to retrieve OCSP response for
	 * @param alternativeUrls a list of {@link String} representing alternative URL sources
	 * @return a list of {@link String} urls
	 */
	protected List<String> getOCSPAccessURLs(CertificateToken certificateToken, List<String> alternativeUrls) {
		if (Utils.isCollectionNotEmpty(alternativeUrls)) {
			LOG.info("OCSP alternative urls : {}", alternativeUrls);
		}

		List<String> ocspAccessUrls = CertificateExtensionsUtils.getOCSPAccessUrls(certificateToken);

		final List<String> ocspUrls = new ArrayList<>();
		ocspUrls.addAll(ocspAccessUrls);
		ocspUrls.addAll(alternativeUrls);
		return ocspUrls;
	}

	/**
	 * Builds an OCSP request for {@code certificateToken}
	 *
	 * @param certificateToken {@link CertificateToken} to retrieve an OCSP token for
	 * @param issuerToken {@link CertificateToken} representing an issuer certificate of {@code certificateToken}
	 * @param nonce byte array containing a unique nonce
	 * @return byte array representing an OCSP request
	 */
	protected byte[] buildOCSPRequest(CertificateToken certificateToken, CertificateToken issuerToken, byte[] nonce) {
		try {
			final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();

			final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerToken, certIDDigestAlgorithm);
			ocspReqBuilder.addRequest(certId);
			/*
			 * The nonce extension is used to bind a request to a response to
			 * prevent replay attacks. RFC 6960 (OCSP) section 4.1.2 such
			 * extensions SHOULD NOT be flagged as critical
			 */
			if (nonce != null) {
				/*
				 * NOTE: The value of the id_pkix_ocsp_nonce extension is DER encoded twice:
				 * - once for the Nonce definition; and
				 * - once for incorporation within the Extension.extnValue field.
				 * Please see DSS-1114 for more detail.
				 */
				DEROctetString encodedNonceValue = new DEROctetString(nonce);
				Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
						new DEROctetString(encodedNonceValue));
				Extensions extensions = new Extensions(extension);
				ocspReqBuilder.setRequestExtensions(extensions);
			}
			final OCSPReq ocspReq = ocspReqBuilder.build();
			return ocspReq.getEncoded();

		} catch (OCSPException | IOException e) {
			throw new DSSException("Cannot build OCSP Request", e);
		}
	}

	/**
	 * Executes a {@code request} to the given {@code ocspAccessLocation} and returns an OCSP basic response, when applicable
	 *
	 * @param ocspAccessLocation {@link String} representing a URL to execute request
	 * @param request byte array containing OCSP request
	 * @return {@link BasicOCSPResp}
	 * @throws IOException if an error occurs on OCSP request execution
	 * @throws OCSPException if an error occurs on OCSP response reading
	 */
	protected BasicOCSPResp executeOCSPRequest(String ocspAccessLocation, byte[] request) throws IOException, OCSPException {
		final byte[] ocspRespBytes = dataLoader.post(ocspAccessLocation, request);
		if (Utils.isArrayNotEmpty(ocspRespBytes)) {
			if (LOG.isTraceEnabled()) {
				LOG.trace(String.format("Obtained OCSPResponse binaries from URL '%s' : %s", ocspAccessLocation, Utils.toBase64(ocspRespBytes)));
			}
			final OCSPResp ocspResp = new OCSPResp(ocspRespBytes);

			OCSPRespStatus status = OCSPRespStatus.fromInt(ocspResp.getStatus());
			if (!OCSPRespStatus.SUCCESSFUL.equals(status)) {
				throw new DSSExternalResourceException(String.format(
						"Ignored OCSP Response from URL '%s' : status -> %s", ocspAccessLocation, status));
			}
			Object responseObject = ocspResp.getResponseObject();
			if (!(responseObject instanceof BasicOCSPResp)) {
				throw new DSSExternalResourceException(
						String.format("OCSP Response Object shall be of type BasicOCSPResp! Obtained type : %s",
								responseObject.getClass().getSimpleName()));
			}
			return (BasicOCSPResp) responseObject;
		}
		throw new DSSExternalResourceException(String.format("OCSP DataLoader for certificate with url '%s' " +
				"responded with an empty byte array!", ocspAccessLocation));
	}

	/**
	 * Verifies whether an OCSP response is valid
	 *
	 * @param basicOCSPResp {@link BasicOCSPResp}
	 * @param latestSingleResponse {@link SingleResp}
	 * @param expectedNonce byte array
	 */
	protected void assertOCSPResponseValid(final BasicOCSPResp basicOCSPResp, final SingleResp latestSingleResponse,
										   final byte[] expectedNonce) {
		/*
		 * RFC 5019 "4. Ensuring an OCSPResponse Is Fresh"
		 *
		 * In general, two mechanisms are available to clients to ensure a
		 * response is fresh. The first uses nonces, and the second is based on
		 * time. In order for time-based mechanisms to work, both clients and
		 * responders MUST have access to an accurate source of time.
		 *
		 * Clients that do not include a nonce in the request MUST ignore any
		 * nonce that may be present in the response.
		 *
		 * Clients MUST check for the existence of the nextUpdate field and MUST
		 * ensure the current time, expressed in GMT time as described in
		 * Section 2.2.4, falls between the thisUpdate and nextUpdate times. If
		 * the nextUpdate field is absent, the client MUST reject the response.
		 */
		if (expectedNonce != null) {
			byte[] receivedNonce = getEmbeddedNonceValue(basicOCSPResp);
			if (receivedNonce == null) {
				alertOnNonexistentNonce();
			} else {
				boolean nonceMatch = Arrays.equals(expectedNonce, receivedNonce);
				if (nonceMatch) {
					// good response
					return;
				} else {
					alertOnInvalidNonce(expectedNonce, receivedNonce);
				}
			}
		}
		assertUpdateTimeValid(latestSingleResponse);
	}
	
	private byte[] getEmbeddedNonceValue(final BasicOCSPResp basicOCSPResp) {
		try {
			Extension extension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
			if (extension != null) {
				ASN1OctetString extnValue = extension.getExtnValue();
				ASN1Primitive value = fromByteArray(extnValue);
				if (value instanceof DEROctetString) {
					return ((DEROctetString) value).getOctets();
				}
				throw new OCSPException("Nonce extension value in OCSP response is not an OCTET STRING");
			}
			return null;

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

	private void assertUpdateTimeValid(SingleResp singleResponse) {
		Date thisUpdate = singleResponse.getThisUpdate();
		if (thisUpdate == null) {
			alertOnInvalidUpdateTime("Obtained OCSP Response does not contain thisUpdate field!");
			return;
		}
		Date nextUpdate = singleResponse.getNextUpdate();
		if (nextUpdate == null) {
			alertOnInvalidUpdateTime("Obtained OCSP Response does not contain nextUpdate field!");
			return;
		}
		Date currentTime = new Date();
		long nextUpdateLimit = nextUpdate.getTime() + nextUpdateTolerancePeriod;
		if (currentTime.before(thisUpdate) || currentTime.after(new Date(nextUpdateLimit))) {
			alertOnInvalidUpdateTime(currentTime, thisUpdate, nextUpdate);
		}
	}

	private void alertOnNonexistentNonce() {
		MessageStatus status = new MessageStatus();
		status.setMessage("No nonce has been retrieved from OCSP response!");
		alertOnNonexistentNonce.alert(status);
	}

	private void alertOnInvalidNonce(byte[] expectedNonce, byte[] receivedNonce) {
		MessageStatus status = new MessageStatus();
		status.setMessage(String.format("Nonce retrieved from OCSP response '#%s' does not match a dispatched nonce '#%s'.",
				Utils.toHex(receivedNonce), Utils.toHex(expectedNonce)));
		alertOnInvalidNonce.alert(status);
	}

	private void alertOnInvalidUpdateTime(String message) {
		MessageStatus status = new MessageStatus();
		status.setMessage(message);
		alertOnInvalidUpdateTime.alert(status);
	}

	private void alertOnInvalidUpdateTime(Date currentTime, Date thisUpdate, Date nextUpdate) {
		alertOnInvalidUpdateTime(String.format("The current time '%s' is out of thisUpdate '%s' - nextUpdate '%s' range!",
				DSSUtils.formatDateToRFC(currentTime), DSSUtils.formatDateToRFC(thisUpdate), DSSUtils.formatDateToRFC(nextUpdate)));
	}

}
