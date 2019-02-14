package eu.europa.esig.dss.x509.revocation.ocsp;

import java.util.Date;
import java.util.Objects;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationOrigin;

public class OCSPTokenBuilder {
	
	/**
	 * Basic OCSP Response received from a relevant OCSP authority
	 */
	private final BasicOCSPResp basicOCSPResp;
	
	/**
	 * Certificate token to get {@link OCSPToken} for
	 */
	private final CertificateToken certificateToken;
	
	/**
	 * If the OCSP url is available
	 */
	private boolean available = false;
	
	/**
	 * Certificate ID
	 */
	private CertificateID certificateID;
	
	/**
	 * The URL which was used to obtain the revocation data (online).
	 */
	private String ocspAccessLocation;
	
	/**
	 * Status of the OCSP response
	 */
	private OCSPRespStatus ocspRespStatus;
	
	/**
	 * Origin of the revocation data (signature or external)
	 */
	private RevocationOrigin origin;
	
	/**
	 * Represents the next update date of the OCSP response.
	 */
	private Date nextUpdate;
	
	/**
	 * Represents the this update date of the OCSP.
	 */
	private Date thisUpdate;
	
	/**
	 * The sent nonce matched with the received one
	 */
	private boolean nonceMatch;

	/**
	 * The OCSP request contained a nonce
	 */
	private boolean useNonce;

	public OCSPTokenBuilder(final BasicOCSPResp basicOCSPResp, final CertificateToken certificateToken) {
		this.basicOCSPResp = basicOCSPResp;
		this.certificateToken = certificateToken;
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
	
	public void setCertificateId(CertificateID certificateID) {
		this.certificateID = certificateID;
	}
	
	public void setOcspRespStatus(OCSPRespStatus ocspRespStatus) {
		this.ocspRespStatus = ocspRespStatus;
	}
	
	public void setAvailable(boolean available) {
		this.available = available;
	}
	
	public void setUseNonce(boolean useNonce) {
		this.useNonce = useNonce;
	}
	
	public void setNonceMatch(boolean nonceMatch) {
		this.nonceMatch = nonceMatch;
	}
	
	public void setNextUpdate(Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}
	
	public void setThisUpdate(Date thisUpdate) {
		this.thisUpdate = thisUpdate;
	}
	
	public void setOrigin(RevocationOrigin origin) {
		this.origin = origin;
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
		if (ocspRespStatus != null) {
			ocspToken.setResponseStatus(ocspRespStatus);
		}
		if (ocspAccessLocation != null) {
			ocspToken.setSourceURL(ocspAccessLocation);
			ocspToken.setRevocationTokenKey(DSSRevocationUtils.getOcspRevocationKey(certificateToken, ocspAccessLocation));
		}
		if (certificateID != null) {
			ocspToken.setCertId(certificateID);
		}
		if (origin != null) {
			ocspToken.setOrigin(origin);
		}
		ocspToken.setAvailable(available);
		ocspToken.setRelatedCertificateID(certificateToken.getDSSIdAsString());

		ocspToken.setBasicOCSPResp(basicOCSPResp);
		
		ocspToken.setUseNonce(useNonce);
		ocspToken.setNonceMatch(nonceMatch);
		
		ocspToken.setThisUpdate(thisUpdate);
		ocspToken.setNextUpdate(nextUpdate);
		ocspToken.initInfo();
		
		return ocspToken;
	}
}
