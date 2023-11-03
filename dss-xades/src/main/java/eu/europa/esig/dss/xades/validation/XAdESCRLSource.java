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

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.xades.definition.XAdESPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.Objects;

/**
 * Retrieves CRL values from an XAdES (-XL) signature.
 */
@SuppressWarnings("serial")
public class XAdESCRLSource extends OfflineCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESCRLSource.class);

	/** The current signature element */
	private final Element signatureElement;

	/** The XAdES XPaths */
	private final XAdESPath xadesPaths;

	/**
	 * The default constructor for XAdESCRLSource.
	 *
	 * @param signatureElement
	 *                         {@code Element} that contains an XML signature
	 * @param xadesPaths
	 *                         adapted {@code XAdESPaths}
	 */
	public XAdESCRLSource(final Element signatureElement, final XAdESPath xadesPaths) {
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
		if (revocationValuesPath == null) {
			return;
		}

		final NodeList revocationValuesNodeList = DomUtils.getNodeList(signatureElement, revocationValuesPath);
		for (int i = 0; i < revocationValuesNodeList.getLength(); i++) {
			final Element revocationValuesElement = (Element) revocationValuesNodeList.item(i);
			final NodeList crlValueNodes = DomUtils.getNodeList(revocationValuesElement, xadesPaths.getCurrentCRLValuesChildren());
			for (int ii = 0; ii < crlValueNodes.getLength(); ii++) {
				try {
					final Element crlValueEl = (Element) crlValueNodes.item(ii);
					String base64EncodedCRL = crlValueEl.getTextContent();
					CRLBinary crlBinary = CRLUtils.buildCRLBinary(Utils.fromBase64(base64EncodedCRL));
					addBinary(crlBinary, revocationOrigin);

				} catch (Exception e) {
					LOG.warn("Unable to build CRLBinary from an obtained element with origin '{}'. Reason : {}", revocationOrigin, e.getMessage(), e);
				}
			}
		}
	}

	private void collectRefs(final String revocationRefsPath, RevocationRefOrigin revocationRefOrigin) {
		if (revocationRefsPath == null) {
			return;
		}

		final NodeList revocationRefsNodeList = DomUtils.getNodeList(signatureElement, revocationRefsPath);
		for (int i = 0; i < revocationRefsNodeList.getLength(); i++) {
			final Element revocationRefsElement = (Element) revocationRefsNodeList.item(i);
			final NodeList crlRefNodes = DomUtils.getNodeList(revocationRefsElement, xadesPaths.getCurrentCRLRefsChildren());
			for (int ii = 0; ii < crlRefNodes.getLength(); ii++) {
				final Element crlRefNode = (Element) crlRefNodes.item(ii);
				CRLRef crlRef = XAdESRevocationRefExtractionUtils.createCRLRef(xadesPaths, crlRefNode);
				if (crlRef !=null) {
					addRevocationReference(crlRef, revocationRefOrigin);
				}
			}
		}
	}

}
