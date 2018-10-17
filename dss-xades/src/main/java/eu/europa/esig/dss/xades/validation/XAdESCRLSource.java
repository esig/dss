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

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * Retrieves CRL values from an XAdES (-XL) signature.
 */
public class XAdESCRLSource extends OfflineCRLSource {

	/**
	 * The default constructor for XAdESCRLSource.
	 *
	 * @param signatureElement
	 *            {@code Element} that contains an XML signature
	 * @param xPathQueryHolder
	 *            adapted {@code XPathQueryHolder}
	 */
	public XAdESCRLSource(final Element signatureElement, final XPathQueryHolder xPathQueryHolder) {
		Objects.requireNonNull(signatureElement, "Signature element cannot be null");
		Objects.requireNonNull(xPathQueryHolder, "XPathQueryHolder cannot be null");

		Set<String> base64Crls = new HashSet<String>();
		collect(base64Crls, signatureElement, xPathQueryHolder.XPATH_CRL_VALUES_ENCAPSULATED_CRL);
		collect(base64Crls, signatureElement, xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_CRL_VALUES);

		for (String base64Crl : base64Crls) {
			addCRLBinary(Utils.fromBase64(base64Crl));
		}
	}

	private void collect(Set<String> base64Crls, Element signatureElement, final String xPathQuery) {
		final NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQuery);
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			final Element crlValueEl = (Element) nodeList.item(ii);
			base64Crls.add(crlValueEl.getTextContent());
		}
	}

}
