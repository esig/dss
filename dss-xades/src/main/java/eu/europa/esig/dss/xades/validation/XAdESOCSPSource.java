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

import java.util.Date;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ResponderId;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureOCSPSource;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * Retrieves OCSP values from an XAdES (XL/LT) signature.
 *
 */
@SuppressWarnings("serial")
public class XAdESOCSPSource extends SignatureOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESOCSPSource.class);

	private final Element signatureElement;

	private final XPathQueryHolder xPathQueryHolder;

	/**
	 * The default constructor for XAdESOCSPSource.
	 *
	 * @param signatureElement
	 *            {@code Element} that contains an XML signature
	 * @param xPathQueryHolder
	 *            adapted {@code XPathQueryHolder}
	 */
	public XAdESOCSPSource(final Element signatureElement, final XPathQueryHolder xPathQueryHolder) {		
		Objects.requireNonNull(signatureElement, "Signature element cannot be null");
		Objects.requireNonNull(xPathQueryHolder, "XPathQueryHolder cannot be null");

		this.signatureElement = signatureElement;
		this.xPathQueryHolder = xPathQueryHolder;
		
		appendContainedOCSPResponses();
	}

	@Override
	public void appendContainedOCSPResponses() {
		// values
		collect(xPathQueryHolder.XPATH_OCSP_VALUES_ENCAPSULATED_OCSP, RevocationOrigin.REVOCATION_VALUES);
		collect(xPathQueryHolder.XPATH_ATTR_REV_ENCAPSULATED_OCSP_VALUES, RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
		collect(xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_OCSP_VALUES, RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
		
		// references
		collectRefs(xPathQueryHolder.XPATH_COMPLETE_REVOCATION_OCSP_REFS, RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		collectRefs(xPathQueryHolder.XPATH_ATTRIBUTE_REVOCATION_OCSP_REFS, RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
	}

	private void collect(String xPathQuery, RevocationOrigin origin) {
		final NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQuery);
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			final Element ocspValueEl = (Element) nodeList.item(ii);
			convertAndAppend(ocspValueEl.getTextContent(), origin);
		}
	}
	
	private void collectRefs(final String xPathQuery, RevocationRefOrigin revocationRefOrigin) {
		final Element ocspRefsElement = DomUtils.getElement(signatureElement, xPathQuery);
		if (ocspRefsElement != null) {
			final NodeList ocspRefNodes = DomUtils.getNodeList(ocspRefsElement, xPathQueryHolder.XPATH__OCSPREF);
			for (int i = 0; i < ocspRefNodes.getLength(); i++) {
				final Element ocspRefElement = (Element) ocspRefNodes.item(i);
				OCSPRef ocspRef = createOCSPRef(ocspRefElement, revocationRefOrigin);
				if (ocspRef != null) {
					addReference(ocspRef, revocationRefOrigin);
				}
			}
		}
	}
	
	private OCSPRef createOCSPRef(final Element ocspRefElement, RevocationRefOrigin revocationRefOrigin) {
		ResponderId responderId = new ResponderId();
		
		final Element responderIdEl = DomUtils.getElement(ocspRefElement, xPathQueryHolder.XPATH__OCSP_RESPONDER_ID_ELEMENT);
		if (responderIdEl != null && responderIdEl.hasChildNodes()) {
			final Element responderIdByName = DomUtils.getElement(responderIdEl, xPathQueryHolder.XPATH__RESPONDER_ID_BY_NAME);
			if (responderIdByName != null) {
				responderId.setName(responderIdByName.getTextContent());
			} else {
				final Element responderIdByKey = DomUtils.getElement(responderIdEl, xPathQueryHolder.XPATH__RESPONDER_ID_BY_KEY);
				if (responderIdByKey != null) {
					responderId.setKey(Utils.fromBase64(responderIdByKey.getTextContent()));
				}
			}
		}
		
		// process only if ResponderId is present
		if (responderId.getName() == null && responderId.getKey() == null) {
			return null;
		}
		
		Date producedAtDate = null;
		final Element producedAtEl = DomUtils.getElement(ocspRefElement, xPathQueryHolder.XPATH__OCSP_PRODUCED_AT_DATETIME);
		if (producedAtEl != null) {
			producedAtDate = DomUtils.getDate(producedAtEl.getTextContent());
		}
		
		// producedAtDate must be present
		if (producedAtDate == null) {
			return null;
		}
		
		final Digest digest = DSSXMLUtils.getRevocationDigest(ocspRefElement, xPathQueryHolder);
		if (digest == null) {
			return null;
		}
		
		return new OCSPRef(digest, producedAtDate, responderId, revocationRefOrigin);
	}

	private void convertAndAppend(String ocspValue, RevocationOrigin origin) {
		try {
			addOCSPResponse(OCSPResponseBinary.build(DSSRevocationUtils.loadOCSPBase64Encoded(ocspValue)), origin);
		} catch (Exception e) {
			LOG.warn("Cannot retrieve OCSP response from '" + ocspValue + "' : " + e.getMessage(), e);
		}
	}

}
