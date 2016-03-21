package eu.europa.esig.dss.client.ocsp;

import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * This enum encapsulates constants defined by BouncyCastle and offers a method to parse an int without exception
 *
 */
public enum OCSPRespStatus {

	/** Response has valid confirmations */
	SUCCESSFUL(OCSPResp.SUCCESSFUL),

	/** Illegal confirmation request */
	MALFORMED_REQUEST(OCSPResp.MALFORMED_REQUEST),

	/** Internal error in issuer */
	INTERNAL_ERROR(OCSPResp.INTERNAL_ERROR),

	/** Try again later */
	TRY_LATER(OCSPResp.TRY_LATER),

	/** (4) is not used */
	UNKNOWN_STATUS(4),

	/** Must sign the request */
	SIG_REQUIRED(OCSPResp.SIG_REQUIRED),

	/** Request unauthorized */
	UNAUTHORIZED(OCSPResp.UNAUTHORIZED);

	private final int statusCode;

	private OCSPRespStatus(int statusCode) {
		this.statusCode = statusCode;
	}

	public static OCSPRespStatus fromInt(int value) {
		for (OCSPRespStatus status : OCSPRespStatus.values()) {
			if (status.statusCode == value) {
				return status;
			}
		}
		return OCSPRespStatus.UNKNOWN_STATUS;
	}

	public int getStatusCode() {
		return statusCode;
	}

}
