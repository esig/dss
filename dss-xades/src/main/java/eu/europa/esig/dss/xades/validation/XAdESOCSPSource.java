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
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

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
 * Retrieves OCSP values from an XAdES (XL/LT) signature.
 *
 */
public class XAdESOCSPSource extends OfflineOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESOCSPSource.class);

	private final Element signatureElement;

	private final XPathQueryHolder xPathQueryHolder;

	private List<BasicOCSPResp> containedOCSPResponses;

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
	public List<BasicOCSPResp> getContainedOCSPResponses() {
		if (containedOCSPResponses == null) {
			Set<String> base64OcspValues = new HashSet<String>();
			collect(base64OcspValues, xPathQueryHolder.XPATH_OCSP_VALUES_ENCAPSULATED_OCSP);
			collect(base64OcspValues, xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_OCSP_VALUE);
			containedOCSPResponses = convert(base64OcspValues);
		}
		return containedOCSPResponses;
	}

	private void collect(Set<String> base64OcspValues, String xPathQuery) {
		final NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQuery);
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			final Element ocspValueEl = (Element) nodeList.item(ii);
			base64OcspValues.add(ocspValueEl.getTextContent());
		}
	}

	private List<BasicOCSPResp> convert(Set<String> base64OcspValues) {
		List<BasicOCSPResp> result = new ArrayList<BasicOCSPResp>();
		for (String base64OcspValue : base64OcspValues) {
			try {
				result.add(DSSRevocationUtils.loadOCSPBase64Encoded(base64OcspValue));
			} catch (Exception e) {
				LOG.warn("Cannot retrieve OCSP response from '" + base64OcspValue + "' : " + e.getMessage(), e);
			}
		}
		return result;
	}

	public List<BasicOCSPResp> getEncapsulatedOCSPValues() {
		Set<String> base64OCSPValues = new HashSet<String>();
		collect(base64OCSPValues, xPathQueryHolder.XPATH_OCSP_VALUES_ENCAPSULATED_OCSP);
		return convert(base64OCSPValues);
	}

	public List<BasicOCSPResp> getTimestampEncapsulatedOCSPValues() {
		Set<String> base64OCSPValues = new HashSet<String>();
		collect(base64OCSPValues, xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_OCSP_VALUE);
		return convert(base64OCSPValues);
	}

}
