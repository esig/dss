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

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureCRLSource;
import eu.europa.esig.dss.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.xades.XAdESUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * Retrieves CRL values from an XAdES (-XL) signature.
 */
@SuppressWarnings("serial")
public class XAdESCRLSource extends SignatureCRLSource {

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

		// values
		collect(signatureElement, xPathQueryHolder.XPATH_CRL_VALUES_ENCAPSULATED_CRL, RevocationOrigin.REVOCATION_VALUES);
		collect(signatureElement, xPathQueryHolder.XPATH_ATTR_REV_ENCAPSULATED_CRL_VALUES, RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
		collect(signatureElement, xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_CRL_VALUES, RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
		
		// references
		collectRefs(signatureElement, xPathQueryHolder, 
				xPathQueryHolder.XPATH_COMPLETE_REVOCATION_CRL_REFS, RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		collectRefs(signatureElement, xPathQueryHolder, 
				xPathQueryHolder.XPATH_ATTRIBUTE_REVOCATION_CRL_REFS, RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
	}

	private void collect(Element signatureElement, final String xPathQuery, RevocationOrigin revocationOrigin) {
		final NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQuery);
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			final Element crlValueEl = (Element) nodeList.item(ii);
			addCRLBinary(Utils.fromBase64(crlValueEl.getTextContent()), revocationOrigin);
		}
	}
	
	private void collectRefs(Element signatureElement, final XPathQueryHolder xPathQueryHolder, 
			final String xPathQuery, RevocationRefOrigin revocationRefOrigin) {
		final Element crlRefsElement = DomUtils.getElement(signatureElement, xPathQuery);
		if (crlRefsElement != null) {
			final NodeList crlRefNodes = DomUtils.getNodeList(crlRefsElement, xPathQueryHolder.XPATH__CRLREF);
			for (int i = 0; i < crlRefNodes.getLength(); i++) {
				final Element crlRefNode = (Element) crlRefNodes.item(i);
				final Digest digest = XAdESUtils.getRevocationDigest(crlRefNode, xPathQueryHolder);
				CRLRef crlRef = new CRLRef(digest, revocationRefOrigin);
				addReference(crlRef, revocationRefOrigin);
			}
		}
	}

}
