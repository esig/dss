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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateRef;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.IssuerSerialInfo;
import eu.europa.esig.dss.x509.SignatureCertificateSource;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * This class provides the mechanism to retrieve certificates contained in a XAdES signature.
 *
 */
@SuppressWarnings("serial")
public class XAdESCertificateSource extends SignatureCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESCertificateSource.class);

	private final Element signatureElement;
	private final XPathQueryHolder xPathQueryHolder;
	
	/**
	 * Cached values
	 */
	private List<CertificateToken> keyInfoCertificates;
	private List<CertificateToken> certificateValues;
	private List<CertificateToken> attrAuthoritiesCertValues;
	private List<CertificateToken> timeStampValidationDataCertValues;
	private List<CertificateRef> signingCertificateValues;
	private List<CertificateRef> completeCertificateRefs;
	private List<CertificateRef> attributeCertificateRefs;

	/**
	 * The default constructor for XAdESCertificateSource. All certificates are extracted during instantiation.
	 *
	 * @param signatureElement
	 *            {@code Element} that contains an XML signature
	 * @param xPathQueryHolder
	 *            adapted {@code XPathQueryHolder}
	 * @param certificatePool
	 *            {@code CertificatePool} to use to declare the found certificates
	 */
	public XAdESCertificateSource(final Element signatureElement, final XPathQueryHolder xPathQueryHolder, final CertificatePool certificatePool) {
		super(certificatePool);
		Objects.requireNonNull(signatureElement, "Element signature must not be null");
		Objects.requireNonNull(xPathQueryHolder, "XPathQueryHolder must not be null");

		this.signatureElement = signatureElement;
		this.xPathQueryHolder = xPathQueryHolder;

		// init
		getKeyInfoCertificates();
		getCertificateValues();
		getAttrAuthoritiesCertValues();
		getTimeStampValidationDataCertValues();

		if (LOG.isInfoEnabled()) {
			LOG.info("+XAdESCertificateSource");
		}
	}

	/**
	 * Returns the list of certificates included in "ds:KeyInfo/ds:X509Data/ds:X509Certificate" node
	 *
	 * @return list of X509Certificate(s)
	 */
	@Override
	public List<CertificateToken> getKeyInfoCertificates() {
		if (keyInfoCertificates == null) {
			keyInfoCertificates = getCertificates(xPathQueryHolder.XPATH_KEY_INFO_X509_CERTIFICATE);
		}
		return keyInfoCertificates;
	}

	@Override
	public List<CertificateToken> getCertificateValues() {
		if (certificateValues == null) {
			certificateValues = getCertificates(xPathQueryHolder.XPATH_ENCAPSULATED_X509_CERTIFICATE);
		}
		return certificateValues;
	}

	@Override
	public List<CertificateToken> getAttrAuthoritiesCertValues() {
		if (attrAuthoritiesCertValues == null) {
			attrAuthoritiesCertValues = getCertificates(xPathQueryHolder.XPATH_AUTH_ENCAPSULATED_X509_CERTIFICATE);
		}
		return attrAuthoritiesCertValues;
	}

	@Override
	public List<CertificateToken> getTimeStampValidationDataCertValues() {
		if (timeStampValidationDataCertValues == null) {
			timeStampValidationDataCertValues = getCertificates(xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_X509_CERTIFICATE);
		}
		return timeStampValidationDataCertValues;
	}

	/**
	 * This method extracts certificates from the given xpath query
	 * 
	 * @param xPathQuery
	 *                   XPath query
	 * @return a list of {@code CertificateToken}
	 */
	private List<CertificateToken> getCertificates(final String xPathQuery) {
		final List<CertificateToken> list = new ArrayList<CertificateToken>();
		final NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQuery);
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			final Element certificateElement = (Element) nodeList.item(ii);
			final byte[] derEncoded = Utils.fromBase64(certificateElement.getTextContent());
			try {
				final CertificateToken cert = DSSUtils.loadCertificate(derEncoded);
				final CertificateToken certToken = addCertificate(cert);
				if (!list.contains(certToken)) {
					list.add(certToken);
				}
			} catch (Exception e) {
				LOG.warn("Unable to parse certificate '{}' : {}", certificateElement.getTextContent(), e.getMessage());
			}
		}
		return list;
	}

	@Override
	public List<CertificateRef> getSigningCertificateValues() {
		if (signingCertificateValues == null) {
			signingCertificateValues = new ArrayList<CertificateRef>();
			NodeList list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNING_CERTIFICATE_CERT);
			if (list != null && list.getLength() != 0) {
				signingCertificateValues.addAll(extractXAdESCertsV1(list, CertificateRefOrigin.SIGNING_CERTIFICATE));
			}
			list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNING_CERTIFICATE_CERT_V2);
			if (list != null && list.getLength() != 0) {
				signingCertificateValues.addAll(extractXAdESCertsV2(list, CertificateRefOrigin.SIGNING_CERTIFICATE));
			}
			if (Utils.isCollectionEmpty(signingCertificateValues)) {
				LOG.warn("No signing certificate tag found");
			}
		}
		return signingCertificateValues;
	}

	@Override
	public List<CertificateRef> getCompleteCertificateRefs() {
		if (completeCertificateRefs == null) {
			completeCertificateRefs = new ArrayList<CertificateRef>();
			NodeList list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CCR_CERT_REFS_CERT);
			if (list != null && list.getLength() != 0) {
				completeCertificateRefs.addAll(extractXAdESCertsV1(list, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS));
			}
			list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CCRV2_CERT_REFS_CERT);
			if (list != null && list.getLength() != 0) {
				completeCertificateRefs.addAll(extractXAdESCertsV2(list, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS));
			}
		}
		return completeCertificateRefs;
	}

	@Override
	public List<CertificateRef> getAttributeCertificateRefs() {
		if (attributeCertificateRefs == null) {
			attributeCertificateRefs = new ArrayList<CertificateRef>();
			NodeList list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ACR_CERT_REFS_CERT);
			if (list != null && list.getLength() != 0) {
				attributeCertificateRefs.addAll(extractXAdESCertsV1(list, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS));
			}
			list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ACRV2_CERT_REFS_CERT);
			if (list != null && list.getLength() != 0) {
				attributeCertificateRefs.addAll(extractXAdESCertsV2(list, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS));
			}
		}
		return attributeCertificateRefs;
	}

	private List<CertificateRef> extractXAdESCertsV1(NodeList list, CertificateRefOrigin location) {
		List<CertificateRef> result = new ArrayList<CertificateRef>();
		for (int i = 0; i < list.getLength(); i++) {
			final Element element = (Element) list.item(i);
			if (element != null) {
				Digest certDigest = DSSXMLUtils.getCertDigest(element, xPathQueryHolder);
				if (certDigest != null) {
					CertificateRef certRef = new CertificateRef();
					certRef.setCertDigest(certDigest);
					certRef.setIssuerInfo(getIssuerV1(element));
					certRef.setOrigin(location);
					result.add(certRef);
				}
			}
		}
		return result;
	}

	private List<CertificateRef> extractXAdESCertsV2(NodeList list, CertificateRefOrigin location) {
		List<CertificateRef> result = new ArrayList<CertificateRef>();
		for (int i = 0; i < list.getLength(); i++) {
			final Element element = (Element) list.item(i);
			if (element != null) {
				Digest certDigest = DSSXMLUtils.getCertDigest(element, xPathQueryHolder);
				if (certDigest != null) {
					CertificateRef certRef = new CertificateRef();
					certRef.setCertDigest(certDigest);
					certRef.setIssuerInfo(getIssuerV2(element));
					certRef.setOrigin(location);
					result.add(certRef);
				}
			}
		}
		return result;
	}

	private IssuerSerialInfo getIssuerV1(Element element) {
		IssuerSerialInfo issuerInfo = new IssuerSerialInfo();

		final Element issuerNameEl = DomUtils.getElement(element, xPathQueryHolder.XPATH__X509_ISSUER_NAME);
		if (issuerNameEl != null) {
			issuerInfo.setIssuerName(DSSUtils.getX500PrincipalOrNull(issuerNameEl.getTextContent()));
		}

		final Element serialNumberEl = DomUtils.getElement(element, xPathQueryHolder.XPATH__X509_SERIAL_NUMBER);
		if (serialNumberEl != null) {
			final String serialNumberText = serialNumberEl.getTextContent();
			issuerInfo.setSerialNumber(new BigInteger(serialNumberText.trim()));
		}

		return issuerInfo;
	}
	
	private IssuerSerialInfo getIssuerV2(Element element) {
		final Element issuerSerialV2Element = DomUtils.getElement(element, xPathQueryHolder.XPATH__X509_ISSUER_V2);
		if (issuerSerialV2Element == null) {
			// Tag issuerSerialV2 is optional
			return null;
		}

		final String textContent = issuerSerialV2Element.getTextContent();
		return DSSASN1Utils.getIssuerInfo(Utils.fromBase64(textContent));
	}

}
