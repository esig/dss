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

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.x509.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * Retrieves OCSP values from an XAdES (>XL) signature.
 *
 */
public class XAdESOCSPSource extends OfflineOCSPSource {

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
		this.signatureElement = signatureElement;
		this.xPathQueryHolder = xPathQueryHolder;
	}

	@Override
	public List<BasicOCSPResp> getContainedOCSPResponses() {
		final List<BasicOCSPResp> list = new ArrayList<BasicOCSPResp>();
		list.addAll(getEncapsulatedOCSPValues());
		list.addAll(getTimestampEncapsulatedOCSPValues());
		return list;
	}

	public List<BasicOCSPResp> getEncapsulatedOCSPValues() {
		return getOCSPValues(xPathQueryHolder.XPATH_OCSP_VALUES_ENCAPSULATED_OCSP);
	}

	public List<BasicOCSPResp> getTimestampEncapsulatedOCSPValues() {
		return getOCSPValues(xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_OCSP_VALUE);
	}

	private List<BasicOCSPResp> getOCSPValues(final String xPathQuery) {
		List<BasicOCSPResp> list = new ArrayList<BasicOCSPResp>();
		final NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQuery);
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			final Element certEl = (Element) nodeList.item(ii);
			try {
				list.add(DSSRevocationUtils.loadOCSPBase64Encoded(certEl.getTextContent()));
			} catch (Exception e) {
				LOG.warn("Cannot retrieve OCSP response from '" + certEl.getTextContent() + "' : " + e.getMessage(), e);
			}
		}
		return list;
	}

}
