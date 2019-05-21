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
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.CertificateRef;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.IssuerSerialInfo;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignatureCertificateSource;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * This class provides the mechanism to retrieve certificates contained in a XAdES signature.
 *
 */
public class XAdESCertificateSource extends SignatureCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESCertificateSource.class);

	private final Element signatureElement;
	private final XPathQueryHolder xPathQueryHolder;

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
		return getCertificates(xPathQueryHolder.XPATH_KEY_INFO_X509_CERTIFICATE);
	}

	@Override
	public List<CertificateToken> getCertificateValues() {
		return getCertificates(xPathQueryHolder.XPATH_ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public List<CertificateToken> getAttrAuthoritiesCertValues() {
		return getCertificates(xPathQueryHolder.XPATH_AUTH_ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public List<CertificateToken> getTimeStampValidationDataCertValues() {
		return getCertificates(xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_X509_CERTIFICATE);
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
		NodeList list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNING_CERTIFICATE_CERT);
		if (list != null && list.getLength() != 0) {
			return extractXAdESCertsV1(list);
		}
		list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNING_CERTIFICATE_CERT_V2);
		if (list != null && list.getLength() != 0) {
			return extractXAdESCertsV2(list);
		}
		LOG.warn("No signing certificate tag found");
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getCompleteCertificateRefs() {
		NodeList list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CCR_CERT_REFS_CERT);
		if (list != null && list.getLength() != 0) {
			return extractXAdESCertsV1(list);
		}
		list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CCRV2_CERT_REFS_CERT);
		if (list != null && list.getLength() != 0) {
			return extractXAdESCertsV2(list);
		}
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getAttributeCertificateRefs() {
		NodeList list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ACR_CERT_REFS_CERT);
		if (list != null && list.getLength() != 0) {
			return extractXAdESCertsV1(list);
		}
		list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ACRV2_CERT_REFS_CERT);
		if (list != null && list.getLength() != 0) {
			return extractXAdESCertsV2(list);
		}
		return Collections.emptyList();
	}

	private List<CertificateRef> extractXAdESCertsV1(NodeList list) {
		List<CertificateRef> result = new ArrayList<CertificateRef>();
		for (int i = 0; i < list.getLength(); i++) {
			final Element element = (Element) list.item(i);
			if (element != null) {
				CertificateRef certRef = new CertificateRef();
				certRef.setCertDigest(getCertDigest(element));
				certRef.setIssuerInfo(getIssuerV1(element));
				result.add(certRef);
			}
		}
		return result;
	}

	private List<CertificateRef> extractXAdESCertsV2(NodeList list) {
		List<CertificateRef> result = new ArrayList<CertificateRef>();
		for (int i = 0; i < list.getLength(); i++) {
			final Element element = (Element) list.item(i);
			if (element != null) {
				CertificateRef certRef = new CertificateRef();
				certRef.setCertDigest(getCertDigest(element));
				certRef.setIssuerInfo(getIssuerV2(element));
				result.add(certRef);
			}
		}
		return result;
	}

	/**
	 * Returns {@link Digest} found in the given {@code element}
	 * @param element {@link Element} to get digest from
	 * @return {@link Digest}
	 */
	public Digest getCertDigest(Element element) {
		final Element certDigestElement = DomUtils.getElement(element, xPathQueryHolder.XPATH__CERT_DIGEST);
		if (certDigestElement == null) {
			return null;
		}
		final Element digestMethodElement = DomUtils.getElement(certDigestElement, xPathQueryHolder.XPATH__DIGEST_METHOD);
		final String xmlAlgorithmName = (digestMethodElement == null) ? null : digestMethodElement.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);

		// The default algorithm is used in case of bad encoded algorithm name
		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(xmlAlgorithmName, DigestAlgorithm.SHA1);

		final Element digestValueElement = DomUtils.getElement(element, xPathQueryHolder.XPATH__CERT_DIGEST_DIGEST_VALUE);
		final byte[] digestValue = (digestValueElement == null) ? null : Utils.fromBase64(digestValueElement.getTextContent());
		return new Digest(digestAlgorithm, digestValue);
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
