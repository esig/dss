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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureCRLSource;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESPaths;

/**
 * Retrieves CRL values from an XAdES (-XL) signature.
 */
@SuppressWarnings("serial")
public class XAdESCRLSource extends SignatureCRLSource {

	private final Element signatureElement;
	private final XAdESPaths xadesPaths;

	/**
	 * The default constructor for XAdESCRLSource.
	 *
	 * @param signatureElement
	 *                         {@code Element} that contains an XML signature
	 * @param xadesPaths
	 *                         adapted {@code XAdESPaths}
	 */
	public XAdESCRLSource(final Element signatureElement, final XAdESPaths xadesPaths) {
		Objects.requireNonNull(signatureElement, "Signature element cannot be null");
		Objects.requireNonNull(xadesPaths, "XAdESPaths cannot be null");

		this.signatureElement = signatureElement;
		this.xadesPaths = xadesPaths;

		// values
		collectValues(xadesPaths.getRevocationValuesPath(), RevocationOrigin.REVOCATION_VALUES);
		collectValues(xadesPaths.getAttributeRevocationValuesPath(), RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
		collectValues(xadesPaths.getTimeStampValidationDataRevocationValuesPath(), RevocationOrigin.TIMESTAMP_VALIDATION_DATA);

		// references
		collectRefs(xadesPaths.getCompleteRevocationRefsPath(), RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		collectRefs(xadesPaths.getAttributeRevocationRefsPath(), RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
	}

	private void collectValues(final String revocationValuesPath, RevocationOrigin revocationOrigin) {
		final Element revocationValuesElement = DomUtils.getElement(signatureElement, revocationValuesPath);
		if (revocationValuesElement != null) {
			final NodeList crlValueNodes = DomUtils.getNodeList(revocationValuesElement, xadesPaths.getCurrentCRLValuesChildren());
			for (int ii = 0; ii < crlValueNodes.getLength(); ii++) {
				final Element crlValueEl = (Element) crlValueNodes.item(ii);
				if (crlValueEl != null) {
					addCRLBinary(Utils.fromBase64(crlValueEl.getTextContent()), revocationOrigin);
				}
			}
		}
	}

	private void collectRefs(final String revocationRefsPath, RevocationRefOrigin revocationRefOrigin) {
		final Element revocationRefsElement = DomUtils.getElement(signatureElement, revocationRefsPath);
		if (revocationRefsElement != null) {
			final NodeList crlRefNodes = DomUtils.getNodeList(revocationRefsElement, xadesPaths.getCurrentCRLRefsChildren());
			for (int i = 0; i < crlRefNodes.getLength(); i++) {
				final Element crlRefNode = (Element) crlRefNodes.item(i);
				final Digest digest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(crlRefNode, xadesPaths.getCurrentDigestAlgAndValue()));
				if (digest != null) {
					CRLRef crlRef = new CRLRef(digest, revocationRefOrigin);
					addReference(crlRef, revocationRefOrigin);
				}
			}
		}
	}

}
