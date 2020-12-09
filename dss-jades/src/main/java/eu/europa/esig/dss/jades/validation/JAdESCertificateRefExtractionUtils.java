package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.jose4j.jwx.HeaderParameterNames;

import java.util.Map;

/**
 * Contains utils for a certificate reference extraction
 */
public final class JAdESCertificateRefExtractionUtils {

	private JAdESCertificateRefExtractionUtils() {
	}

	/**
	 * Parses the xRefs component value and returns {@code CertificateRef}
	 *
	 * @param certificateRefMap a map representing the xRefs component value
	 * @return {@link CertificateRef} of the value has been parsed successfully, FALSE otherwise
	 */
	public static CertificateRef createCertificateRef(Map<?, ?> certificateRefMap) {
		IssuerSerial issuerSerial = DSSJsonUtils.getIssuerSerial((String) certificateRefMap.get(HeaderParameterNames.KEY_ID));

		Digest digest = DSSJsonUtils.getDigest(certificateRefMap);
		if (digest != null) {
			CertificateRef certificateRef = new CertificateRef();
			certificateRef.setCertDigest(digest);
			if (issuerSerial != null) {
				certificateRef.setCertificateIdentifier(DSSASN1Utils.toCertificateIdentifier(issuerSerial));
			}
			return certificateRef;
		}

		return null;
	}

}
