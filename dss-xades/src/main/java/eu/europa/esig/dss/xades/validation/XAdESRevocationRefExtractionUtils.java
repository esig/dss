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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.xades.definition.XAdESPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.security.auth.x500.X500Principal;
import java.util.Date;

/**
 * Utils for a XAdES revocation refs extraction
 */
public final class XAdESRevocationRefExtractionUtils {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESRevocationRefExtractionUtils.class);

	private XAdESRevocationRefExtractionUtils() {
	}

	/**
	 * Extracts a {@code OCSPRef} from a {@code ocspRefElement}
	 *
	 * @param xadesPaths {@link XAdESPath}
	 * @param ocspRefElement {@link Element} ocspRef element
	 * @return {@link OCSPRef}
	 */
	public static OCSPRef createOCSPRef(final XAdESPath xadesPaths, final Element ocspRefElement) {

		Digest digest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(ocspRefElement, xadesPaths.getCurrentDigestAlgAndValue()));

		ResponderId responderId = getOCSPResponderId(xadesPaths, ocspRefElement);
		if (responderId == null) {
			LOG.warn("Skipped OCSPRef (missing OCSPIdentifier / ResponderID)");
			return null;
		}

		Date producedAtDate = getOCSPProducedAtDate(xadesPaths, ocspRefElement);
		if (producedAtDate == null) {
			LOG.warn("Skipped OCSPRef (missing OCSPIdentifier / ProducedAt)");
			return null;
		}

		return new OCSPRef(digest, producedAtDate, responderId);
	}

	private static Date getOCSPProducedAtDate(final XAdESPath xadesPaths, final Element ocspRefElement) {
		Date producedAtDate = null;
		final Element producedAtEl = DomUtils.getElement(ocspRefElement, xadesPaths.getCurrentOCSPRefProducedAt());
		if (producedAtEl != null) {
			producedAtDate = DomUtils.getDate(producedAtEl.getTextContent());
		}
		return producedAtDate;
	}

	private static ResponderId getOCSPResponderId(final XAdESPath xadesPaths, final Element ocspRefElement) {
		X500Principal responderName = null;
		byte[] ski = null;
		String currentOCSPRefResponderIDByName = xadesPaths.getCurrentOCSPRefResponderIDByName();
		String currentOCSPRefResponderIDByKey = xadesPaths.getCurrentOCSPRefResponderIDByKey();
		if (currentOCSPRefResponderIDByName != null && currentOCSPRefResponderIDByKey != null) {
			final Element responderIdByName = DomUtils.getElement(ocspRefElement, currentOCSPRefResponderIDByName);
			if (responderIdByName != null) {
				responderName = DSSUtils.getX500PrincipalOrNull(responderIdByName.getTextContent());
			}

			final Element responderIdByKey = DomUtils.getElement(ocspRefElement, currentOCSPRefResponderIDByKey);
			if (responderIdByKey != null) {
				ski = Utils.fromBase64(responderIdByKey.getTextContent());
			}
		} else {
			final Element responderIdElement = DomUtils.getElement(ocspRefElement, xadesPaths.getCurrentOCSPRefResponderID());
			if (responderIdElement != null) {
				responderName = DSSUtils.getX500PrincipalOrNull(responderIdElement.getTextContent());
			}
		}

		if (responderName != null || Utils.isArrayNotEmpty(ski)) {
			return new ResponderId(responderName, ski);
		}
		return null;
	}

	/**
	 * Extracts a {@code CRLRef} from a {@code crlRefElement}
	 *
	 * @param xadesPaths {@link XAdESPath}
	 * @param crlRefElement {@link Element} crlRef element
	 * @return {@link OCSPRef}
	 */
	public static CRLRef createCRLRef(XAdESPath xadesPaths, Element crlRefElement) {
		final Digest digest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(crlRefElement, xadesPaths.getCurrentDigestAlgAndValue()));
		if (digest == null) {
			LOG.warn("Skipped CRLRef (missing DigestAlgAndValue)");
			return null;
		}
		// TODO CRLIdentifier
		return new CRLRef(digest);
	}

}
