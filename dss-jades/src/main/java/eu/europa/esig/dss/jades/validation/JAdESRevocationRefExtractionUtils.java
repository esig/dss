package eu.europa.esig.dss.jades.validation;

import java.math.BigInteger;
import java.util.Date;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.utils.Utils;

public final class JAdESRevocationRefExtractionUtils {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESRevocationRefExtractionUtils.class);

	private JAdESRevocationRefExtractionUtils() {
	}

	public static OCSPRef createOCSPRef(final Map<?,?> ocpRef) {
		ResponderId responderId = null;
		Date producedAt = null;

		try {
			Map<?, ?> ocspId = (Map<?, ?>) ocpRef.get(JAdESHeaderParameterNames.OCSP_ID);
			if (Utils.isMapNotEmpty(ocspId)) {
				producedAt = DSSJsonUtils.getDate((String) ocspId.get(JAdESHeaderParameterNames.PRODUCED_AT));
				responderId = getResponderId(ocspId);
			}

			Digest digest = DSSJsonUtils.getDigest(ocpRef);
			if (digest != null) {
				return new OCSPRef(digest, producedAt, responderId);
			} else {
				LOG.warn("Missing digest information in OCSPRef");
			}

		} catch (Exception e) {
			LOG.warn("Unable to extract OCSPRef. Reason : {}", e.getMessage(), e);
		}
		return null;
	}

	private static ResponderId getResponderId(Map<?, ?> ocspId) {
		Map<?, ?> responderIdMap = (Map<?, ?>) ocspId.get(JAdESHeaderParameterNames.RESPONDER_ID);
		if (Utils.isMapNotEmpty(responderIdMap)) {

			X500Principal subjectX500Principal = null;
			byte[] ski = null;

			String byNameB64 = (String) responderIdMap.get(JAdESHeaderParameterNames.BY_NAME);
			if (Utils.isStringNotEmpty(byNameB64) && Utils.isBase64Encoded(byNameB64)) {
				subjectX500Principal = DSSASN1Utils.toX500Principal(X500Name.getInstance(Utils.fromBase64(byNameB64)));
			}

			String byKeyB64 = (String) responderIdMap.get(JAdESHeaderParameterNames.BY_KEY);
			if (Utils.isStringNotEmpty(byKeyB64) && Utils.isBase64Encoded(byKeyB64)) {
				ski = Utils.fromBase64(byKeyB64);
			}

			if (subjectX500Principal != null || Utils.isArrayNotEmpty(ski)) {
				return new ResponderId(subjectX500Principal, ski);
			}
		}
		return null;
	}

	public static CRLRef createCRLRef(Map<?, ?> crlRefMap) {

		X500Name crlIssuer = null;
		Date crlIssuedTime = null;
		BigInteger crlNumber = null;

		try {
			Map<?, ?> crlId = (Map<?, ?>) crlRefMap.get(JAdESHeaderParameterNames.CRL_ID);
			if (Utils.isMapNotEmpty(crlId)) {
				String issuerB64 = (String) crlId.get(JAdESHeaderParameterNames.ISSUER);
				if (Utils.isStringNotEmpty(issuerB64) && Utils.isBase64Encoded(issuerB64)) {
					crlIssuer = X500Name.getInstance(Utils.fromBase64(issuerB64));
				}

				String issueTimeStr = (String) crlId.get(JAdESHeaderParameterNames.ISSUE_TIME);
				if (Utils.isStringNotEmpty(issueTimeStr)) {
					crlIssuedTime = DSSJsonUtils.getDate(issueTimeStr);
				}

				String crlNumberString = (String) crlId.get(JAdESHeaderParameterNames.NUMBER);
				if (Utils.isStringNotEmpty(crlNumberString)) {
					crlNumber = BigInteger.valueOf(Long.parseLong(crlNumberString));
				}
			}

			Digest digest = DSSJsonUtils.getDigest(crlRefMap);
			if (digest != null) {
				CRLRef crlRef = new CRLRef(digest);
				crlRef.setCrlIssuer(crlIssuer);
				crlRef.setCrlIssuedTime(crlIssuedTime);
				crlRef.setCrlNumber(crlNumber);
				return crlRef;

			} else {
				LOG.warn("Missing digest information in CRLRef");
			}

		} catch (Exception e) {
			LOG.warn("Unable to extract a CRLRef. Reason : {}", e.getMessage(), e);
		}
		return null;
	}

}
