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

import java.security.cert.X509CRL;
import java.util.ArrayList;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;

/**
 * Retrieves CRL values from an XAdES (-XL) signature.
 */
public class XAdESCRLSource extends OfflineCRLSource {

    /**
     * The default constructor for XAdESCRLSource.
     *
     * @param signatureElement {@code Element} that contains an XML signature
     * @param xPathQueryHolder adapted {@code XPathQueryHolder}
     */
    public XAdESCRLSource(final Element signatureElement, final XPathQueryHolder xPathQueryHolder) {

        if (signatureElement == null) {

            throw new NullPointerException("signatureElement");
        }
        if (xPathQueryHolder == null) {

            throw new NullPointerException("xPathQueryHolder");
        }
	    x509CRLList = new ArrayList<X509CRL>();
        addCRLs(signatureElement, xPathQueryHolder.XPATH_ENCAPSULATED_CRL_VALUE);
        addCRLs(signatureElement, xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_CRL_VALUE);
    }

    private void addCRLs(Element signatureElement, final String xPathQuery) {

        final NodeList nodeList = DSSXMLUtils.getNodeList(signatureElement, xPathQuery);
        for (int ii = 0; ii < nodeList.getLength(); ii++) {

            final Element certEl = (Element) nodeList.item(ii);
            final String textContent = certEl.getTextContent();
            final X509CRL x509CRL = DSSUtils.loadCRLBase64Encoded(textContent);
            if (!x509CRLList.contains(x509CRL)) {

                x509CRLList.add(x509CRL);
            }
        }
    }
}
