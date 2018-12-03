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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DomUtils;
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

	private List<CertificateToken> keyInfoCerts;
	private List<CertificateToken> encapsulatedCerts;
	private List<CertificateToken> timestampValidationDataCerts;

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

		encapsulatedCerts = getCertificates(xPathQueryHolder.XPATH_ENCAPSULATED_X509_CERTIFICATE);
		keyInfoCerts = getCertificates(xPathQueryHolder.XPATH_KEY_INFO_X509_CERTIFICATE);
		timestampValidationDataCerts = getCertificates(xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_X509_CERTIFICATE);

		if (LOG.isInfoEnabled()) {
			LOG.info("+XAdESCertificateSource");
		}
	}

	/**
	 * This method extracts certificates from the given xpath query
	 * 
	 * @param xPathQuery
	 *            XPath query
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

	/**
	 * Returns the list of certificates included in
	 * ".../xades:UnsignedSignatureProperties/xades:CertificateValues/xades:EncapsulatedX509Certificate" node
	 *
	 * @return list of X509Certificate(s)
	 */
	@Override
	public List<CertificateToken> getEncapsulatedCertificates() throws DSSException {
		return encapsulatedCerts;
	}

	/**
	 * Returns the list of certificates included in "ds:KeyInfo/ds:X509Data/ds:X509Certificate" node
	 *
	 * @return list of X509Certificate(s)
	 */
	@Override
	public List<CertificateToken> getKeyInfoCertificates() throws DSSException {
		return keyInfoCerts;
	}

	/**
	 * Returns the list of certificates included in "xades141:TimeStampValidationData/xades132:CertificateValues" node
	 *
	 * @return
	 * @throws eu.europa.esig.dss.DSSException
	 */
	public List<CertificateToken> getTimestampCertificates() throws DSSException {
		return timestampValidationDataCerts;
	}
}
