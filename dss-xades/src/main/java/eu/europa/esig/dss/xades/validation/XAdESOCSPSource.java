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
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.xades.definition.XAdESPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.Objects;

/**
 * Retrieves OCSP values from an XAdES (XL/LT) signature.
 *
 */
@SuppressWarnings("serial")
public class XAdESOCSPSource extends OfflineOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESOCSPSource.class);

	/** The current signature element */
	private final Element signatureElement;

	/** The XAdES XPaths */
	private final XAdESPath xadesPaths;

	/**
	 * The default constructor for XAdESOCSPSource.
	 *
	 * @param signatureElement
	 *                         {@code Element} that contains an XML signature
	 * @param xadesPaths
	 *                         adapted {@code XAdESPaths}
	 */
	public XAdESOCSPSource(final Element signatureElement, final XAdESPath xadesPaths) {
		Objects.requireNonNull(signatureElement, "Signature element cannot be null");
		Objects.requireNonNull(xadesPaths, "XAdESPaths cannot be null");

		this.signatureElement = signatureElement;
		this.xadesPaths = xadesPaths;
		
		appendContainedOCSPResponses();
	}

	private void appendContainedOCSPResponses() {
		// values
		collectValues(xadesPaths.getRevocationValuesPath(), RevocationOrigin.REVOCATION_VALUES);
		collectValues(xadesPaths.getAttributeRevocationValuesPath(), RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
		collectValues(xadesPaths.getTimeStampValidationDataRevocationValuesPath(), RevocationOrigin.TIMESTAMP_VALIDATION_DATA);

		// references
		collectRefs(xadesPaths.getCompleteRevocationRefsPath(), RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		collectRefs(xadesPaths.getAttributeRevocationRefsPath(), RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
	}

	private void collectValues(String revocationValuesPath, RevocationOrigin origin) {
		if (revocationValuesPath == null) {
			return;
		}

		final NodeList revocationValuesNodeList = DomUtils.getNodeList(signatureElement, revocationValuesPath);
		for (int i = 0; i < revocationValuesNodeList.getLength(); i++) {
			final Element revocationValuesElement = (Element) revocationValuesNodeList.item(i);
			final NodeList ocspValueNodes = DomUtils.getNodeList(revocationValuesElement, xadesPaths.getCurrentOCSPValuesChildren());
			for (int ii = 0; ii < ocspValueNodes.getLength(); ii++) {
				final Element ocspValueEl = (Element) ocspValueNodes.item(ii);
				if (ocspValueEl != null) {
					convertAndAppend(ocspValueEl.getTextContent(), origin);
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
			final NodeList ocspRefNodes = DomUtils.getNodeList(revocationRefsElement, xadesPaths.getCurrentOCSPRefsChildren());
			for (int ii = 0; ii < ocspRefNodes.getLength(); ii++) {
				final Element ocspRefElement = (Element) ocspRefNodes.item(ii);
				if (ocspRefElement != null) {
					OCSPRef ocspRef = XAdESRevocationRefExtractionUtils.createOCSPRef(xadesPaths, ocspRefElement);
					if (ocspRef != null) {
						addRevocationReference(ocspRef, revocationRefOrigin);
					}
				}
			}
		}
	}
	
	private void convertAndAppend(String ocspValue, RevocationOrigin origin) {
		try {
			addBinary(OCSPResponseBinary.build(DSSRevocationUtils.loadOCSPBase64Encoded(ocspValue)), origin);
		} catch (Exception e) {
			LOG.warn("Cannot retrieve OCSP response from '{}' : {}", ocspValue, e.getMessage(), e);
		}
	}

}
