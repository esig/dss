package eu.europa.esig.dss.x509.revocation.ocsp;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationOrigin;

public class OCSPTokenBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPTokenBuilder.class);
	
	/**
	 * Basic OCSP Response received from a relevant OCSP authority
	 */
	private final BasicOCSPResp basicOCSPResp;
	
	/**
	 * Certificate token to get {@link OCSPToken} for
	 */
	private final CertificateToken certificateToken;
	
	/**
	 * Issuer's certificate token of the used certificateToken
	 */
	private final CertificateToken issuerCertificateToken;
	
	/**
	 * If the OCSP url is available
	 */
	private boolean available = false;
	
	/**
	 * The URL which was used to obtain the revocation data (online).
	 */
	private String ocspAccessLocation;
	
	/**
	 * Status of the OCSP response
	 */
	private OCSPRespStatus responseStatus;
	
	/**
	 * Origins of the revocation data (signature or external)
	 */
	private List<RevocationOrigin> origins;
	
	/**
	 * This variable is used to prevent the replay attack.
	 */
	private BigInteger nonce;
	
	public OCSPTokenBuilder(final OCSPResp ocspResp, final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) throws OCSPException {
		this((BasicOCSPResp) ocspResp.getResponseObject(), certificateToken, issuerCertificateToken);
		this.responseStatus = OCSPRespStatus.fromInt(ocspResp.getStatus());
		if (OCSPRespStatus.SUCCESSFUL.equals(this.responseStatus)) {
			this.available = true;
		}
	}

	public OCSPTokenBuilder(final BasicOCSPResp basicOCSPResp, final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
		this.basicOCSPResp = basicOCSPResp;
		this.certificateToken = certificateToken;
		this.issuerCertificateToken = issuerCertificateToken;
	}

	/**
	 * This sets the revocation data source URL. It is only used in case of
	 * {@code OnlineSource}.
	 *
	 * @param sourceURL
	 *            the URL which was used to retrieve this CRL
	 */
	public void setSourceURL(final String sourceURL) {
		this.ocspAccessLocation = sourceURL;
	}
	
	public void setAvailable(boolean available) {
		this.available = available;
	}
	
	public void setOCSPResponseStatus(OCSPRespStatus respStatus) {
		this.responseStatus = respStatus;
	}
	
	public void setNonce(BigInteger nonce) {
		this.nonce = nonce;
	}
	
	public void setOrigins(List<RevocationOrigin> origins) {
		this.origins = origins;
	}
	
	/**
	 * Build {@link OCSPToken} based on the provided parameters
	 * @return {@link OCSPToken} object
	 * @throws OCSPException on case of error
	 */
	public OCSPToken build() throws OCSPException {
		Objects.requireNonNull(basicOCSPResp, "The basic OCSP response must be filled");
		Objects.requireNonNull(certificateToken, "The Certificate token must be filled");
		OCSPToken ocspToken = new OCSPToken();
		if (ocspAccessLocation != null) {
			ocspToken.setSourceURL(ocspAccessLocation);
			ocspToken.setRevocationTokenKey(DSSRevocationUtils.getOcspRevocationKey(certificateToken, ocspAccessLocation));
		}
		ocspToken.setCertId(DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken));
		if (origins != null) {
			ocspToken.setOrigins(origins);
		}
		ocspToken.setAvailable(available);
		ocspToken.setResponseStatus(responseStatus);
		ocspToken.setRelatedCertificate(certificateToken);
		
		ocspToken.setBasicOCSPResp(basicOCSPResp);
		if (nonce != null) {
			ocspToken.setUseNonce(true);
			boolean nonceMatch = isNonceMatch(basicOCSPResp, nonce);
			if (nonceMatch) {
				ocspToken.setNonceMatch(true);
			} else {
				throw new OCSPException("Nonce received from OCSP response does not match a dispatched nonce.");
			}
		}
		
		ocspToken.initInfo();
		
		return ocspToken;
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
