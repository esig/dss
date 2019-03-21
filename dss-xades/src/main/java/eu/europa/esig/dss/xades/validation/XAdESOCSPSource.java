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

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.ocsp.SignatureOCSPSource;
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
	}
	
	

	@Override
	public void appendContainedOCSPResponses() {
		collect(xPathQueryHolder.XPATH_OCSP_VALUES_ENCAPSULATED_OCSP, RevocationOrigin.INTERNAL_REVOCATION_VALUES);
		// TODO: collect INTERNAL_ATTRIBUTE_REVOCATION_VALUES
		collect(xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_OCSP_VALUE, RevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES);
	}

	private void collect(String xPathQuery, RevocationOrigin origin) {
		final NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQuery);
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			final Element ocspValueEl = (Element) nodeList.item(ii);
			convertAndAppend(ocspValueEl.getTextContent(), origin);
		}
	}

	private void convertAndAppend(String ocspValue, RevocationOrigin origin) {
		try {
			ocspResponses.put(DSSRevocationUtils.loadOCSPBase64Encoded(ocspValue), origin);
		} catch (Exception e) {
			LOG.warn("Cannot retrieve OCSP response from '" + ocspValue + "' : " + e.getMessage(), e);
		}
	}

}
