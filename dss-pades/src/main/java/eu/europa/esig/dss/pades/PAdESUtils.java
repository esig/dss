package eu.europa.esig.dss.pades;

import java.util.Date;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

public final class PAdESUtils {
	
	private PAdESUtils() {}
	
	public static String getSignatureName(PAdESSignatureParameters parameters) {
		if (parameters.getSignatureName() != null) {
			return parameters.getSignatureName();
		} else {

			CertificateToken token = parameters.getSigningCertificate();
			Date date = parameters.bLevel().getSigningDate();
			String encodedDate = Utils
					.toHex(DSSUtils.digest(DigestAlgorithm.SHA1, Long.toString(date.getTime()).getBytes()));

			if (token == null) {
				return "Unknown signer" + encodedDate;
			} else {
				return DSSASN1Utils.getHumanReadableName(token) + encodedDate;
			}
		}
	}

}
