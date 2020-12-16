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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.util.Date;
import java.util.Map;

/**
 * Contains utils to extract revocation references
 */
public final class JAdESRevocationRefExtractionUtils {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESRevocationRefExtractionUtils.class);

	private JAdESRevocationRefExtractionUtils() {
	}

	/**
	 * Extract an {@code OCSPRef} from 'ocpsRefs' header
	 *
	 * @param ocpRef map representing the value of 'ocpsRefs' header
	 * @return {@link OCSPRef}
	 */
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

	/**
	 * Extract an {@code CRLRef} from 'crlRefs' header
	 *
	 * @param crlRefMap map representing the value of 'crlRefs' header
	 * @return {@link CRLRef}
	 */
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
