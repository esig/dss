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
import eu.europa.esig.dss.xades.XAdESPaths;

/**
 * Retrieves OCSP values from an XAdES (XL/LT) signature.
 *
 */
@SuppressWarnings("serial")
public class XAdESOCSPSource extends SignatureOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESOCSPSource.class);

	private final Element signatureElement;

	private final XAdESPaths xadesPaths;

	/**
	 * The default constructor for XAdESOCSPSource.
	 *
	 * @param signatureElement
	 *                         {@code Element} that contains an XML signature
	 * @param xadesPaths
	 *                         adapted {@code XAdESPaths}
	 */
	public XAdESOCSPSource(final Element signatureElement, final XAdESPaths xadesPaths) {
		Objects.requireNonNull(signatureElement, "Signature element cannot be null");
		Objects.requireNonNull(xadesPaths, "XAdESPaths cannot be null");

		this.signatureElement = signatureElement;
		this.xadesPaths = xadesPaths;
		
		appendContainedOCSPResponses();
	}

	@Override
	public void appendContainedOCSPResponses() {
		// values
		collectValues(xadesPaths.getRevocationValuesPath(), RevocationOrigin.REVOCATION_VALUES);
		collectValues(xadesPaths.getAttributeRevocationValuesPath(), RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
		collectValues(xadesPaths.getTimeStampValidationDataRevocationValuesPath(), RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
		
		// references
		collectRefs(xadesPaths.getCompleteRevocationRefsPath(), RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		collectRefs(xadesPaths.getAttributeRevocationRefsPath(), RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
	}

	private void collectValues(String revocationValuesPath, RevocationOrigin origin) {
		final Element revocationValuesElement = DomUtils.getElement(signatureElement, revocationValuesPath);
		if (revocationValuesElement != null) {
			final NodeList ocspValueNodes = DomUtils.getNodeList(revocationValuesElement, xadesPaths.getCurrentOCSPValuesChildren());
			for (int ii = 0; ii < ocspValueNodes.getLength(); ii++) {
				final Element ocspValueEl = (Element) ocspValueNodes.item(ii);
				convertAndAppend(ocspValueEl.getTextContent(), origin);
			}
		}
	}
	
	private void collectRefs(final String revocationRefsPath, RevocationRefOrigin revocationRefOrigin) {
		final Element revocationRefsElement = DomUtils.getElement(signatureElement, revocationRefsPath);
		if (revocationRefsElement != null) {
			final NodeList ocspRefNodes = DomUtils.getNodeList(revocationRefsElement, xadesPaths.getCurrentOCSPRefsChildren());
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
		
		final Element responderIdByName = DomUtils.getElement(ocspRefElement, xadesPaths.getCurrentOCSPRefResponderIDByName());
		if (responderIdByName != null) {
			responderId.setName(responderIdByName.getTextContent());
		}

		final Element responderIdByKey = DomUtils.getElement(ocspRefElement, xadesPaths.getCurrentOCSPRefResponderIDByKey());
		if (responderIdByKey != null) {
			responderId.setKey(Utils.fromBase64(responderIdByKey.getTextContent()));
		}
		
		// process only if ResponderId is present
		if (responderId.getName() == null && responderId.getKey() == null) {
			return null;
		}
		
		Date producedAtDate = null;
		final Element producedAtEl = DomUtils.getElement(ocspRefElement, xadesPaths.getCurrentOCSPRefProducedAt());
		if (producedAtEl != null) {
			producedAtDate = DomUtils.getDate(producedAtEl.getTextContent());
		}
		
		// producedAtDate must be present
		if (producedAtDate == null) {
			return null;
		}
		
		final Digest digest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(ocspRefElement, xadesPaths.getCurrentDigestAlgAndValue()));
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
