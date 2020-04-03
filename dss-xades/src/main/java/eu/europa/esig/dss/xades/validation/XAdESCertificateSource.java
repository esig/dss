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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.xades.definition.XAdESPaths;

/**
 * This class provides the mechanism to retrieve certificates contained in a XAdES signature.
 *
 */
@SuppressWarnings("serial")
public class XAdESCertificateSource extends SignatureCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESCertificateSource.class);

	private final Element signatureElement;
	private final XAdESPaths xadesPaths;
	
	/**
	 * The default constructor for XAdESCertificateSource. All certificates are
	 * extracted during instantiation.
	 *
	 * @param signatureElement
	 *                         {@code Element} that contains an XML signature
	 * @param xadesPaths
	 *                         adapted {@code XAdESPaths}
	 */
	public XAdESCertificateSource(final Element signatureElement, final XAdESPaths xadesPaths) {
		Objects.requireNonNull(signatureElement, "Element signature must not be null");
		Objects.requireNonNull(xadesPaths, "XAdESPaths must not be null");

		this.signatureElement = signatureElement;
		this.xadesPaths = xadesPaths;

		// init
		extractCertificates(XMLDSigPaths.KEY_INFO_X509_CERTIFICATE_PATH, CertificateOrigin.KEY_INFO);
		extractCertificates(xadesPaths.getEncapsulatedCertificateValuesPath(), CertificateOrigin.CERTIFICATE_VALUES);
		extractCertificates(xadesPaths.getEncapsulatedAttrAuthoritiesCertValuesPath(), CertificateOrigin.ATTR_AUTORITIES_CERT_VALUES);
		extractCertificates(xadesPaths.getEncapsulatedTimeStampValidationDataCertValuesPath(), CertificateOrigin.TIMESTAMP_VALIDATION_DATA);

		extractCertificateRefs(xadesPaths.getSigningCertificatePath(), xadesPaths.getSigningCertificateV2Path(), CertificateRefOrigin.SIGNING_CERTIFICATE);
		extractCertificateRefs(xadesPaths.getCompleteCertificateRefsCertPath(), xadesPaths.getCompleteCertificateRefsV2CertPath(),
				CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
		extractCertificateRefs(xadesPaths.getAttributeCertificateRefsCertPath(), xadesPaths.getAttributeCertificateRefsV2CertPath(),
				CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS);

		if (LOG.isInfoEnabled()) {
			LOG.info("+XAdESCertificateSource");
		}
	}

	/**
	 * This method extracts certificates from the given xpath query
	 * 
	 * @param xPathQuery XPath query
	 * @param origin     the certificate origin
	 */
	private void extractCertificates(final String xPathQuery, CertificateOrigin origin) {
		if (xPathQuery == null) {
			return;
		}
		final NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQuery);
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			final Element certificateElement = (Element) nodeList.item(ii);
			try {
				final byte[] derEncoded = Utils.fromBase64(certificateElement.getTextContent());
				final CertificateToken cert = DSSUtils.loadCertificate(derEncoded);
				addCertificate(cert, origin);
			} catch (Exception e) {
				LOG.warn("Unable to parse certificate '{}' : {}", certificateElement.getTextContent(), e.getMessage());
			}
		}
	}

	/**
	 * This method extracts certificate references from the given xpath queries
	 * 
	 * @param xpathV1 XPath query for certificate reference V1
	 * @param xpathV2 XPath query for certificate reference V2
	 * @param origin  the certificate reference origin
	 */
	private void extractCertificateRefs(String xpathV1, String xpathV2, CertificateRefOrigin origin) {
		if (xpathV1 != null) {
			NodeList certRefNodeList = DomUtils.getNodeList(signatureElement, xpathV1);
			if (certRefNodeList != null) {
				extractXAdESCertsV1(certRefNodeList, origin);
			}
		}
		if (xpathV2 != null) {
			NodeList certRefNodeList = DomUtils.getNodeList(signatureElement, xpathV2);
			if (certRefNodeList != null) {
				extractXAdESCertsV2(certRefNodeList, origin);
			}
		}
	}

	private void extractXAdESCertsV1(NodeList certNodeList, CertificateRefOrigin origin) {
		for (int i = 0; i < certNodeList.getLength(); i++) {
			final Element certRefElement = (Element) certNodeList.item(i);
			final CertificateRef certificateRef = XAdESCertificateRefExtractionUtils.createCertificateRefFromV1(certRefElement, xadesPaths);
			if (certificateRef != null) {
				certificateRef.setOrigin(origin);
				addCertificateRef(certificateRef, origin);
			}
		}
	}

	private void extractXAdESCertsV2(NodeList certNodeList, CertificateRefOrigin origin) {
		for (int i = 0; i < certNodeList.getLength(); i++) {
			final Element certRefElement = (Element) certNodeList.item(i);
			final CertificateRef certificateRef = XAdESCertificateRefExtractionUtils.createCertificateRefFromV2(certRefElement, xadesPaths);
			if (certificateRef != null) {
				certificateRef.setOrigin(origin);
				addCertificateRef(certificateRef, origin);
			}
		}
	}

}
