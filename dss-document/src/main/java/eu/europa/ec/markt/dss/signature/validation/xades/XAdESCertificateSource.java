/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.validation.xades;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.SignatureCertificateSource;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

/**
 * This class provides the mechanism to retrieve certificates contained in a XAdES signature.
 *
 */
public class XAdESCertificateSource extends SignatureCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESCertificateSource.class);

	private final Element signatureElement;

	private final XPathQueryHolder xPathQueryHolder;

	private List<CertificateToken> keyInfoCerts;

	private List<CertificateToken> encapsulatedCerts;

	private List<CertificateToken> timestampValidationDataCerts;

	/**
	 * The default constructor for XAdESCertificateSource. All certificates are extracted during instantiation.
	 *
	 * @param signatureElement {@code Element} that contains an XML signature
	 * @param xPathQueryHolder adapted {@code XPathQueryHolder}
	 * @param certificatePool  {@code CertificatePool} to use to declare the found certificates
	 */
	public XAdESCertificateSource(final Element signatureElement, final XPathQueryHolder xPathQueryHolder, final CertificatePool certificatePool) {

		super(certificatePool);
		if (signatureElement == null) {

			throw new DSSNullException(Element.class, "signatureElement");
		}
		if (xPathQueryHolder == null) {

			throw new DSSNullException(XPathQueryHolder.class, "xPathQueryHolder");
		}
		this.signatureElement = signatureElement;
		this.xPathQueryHolder = xPathQueryHolder;

		if (certificateTokens == null) {

			certificateTokens = new ArrayList<CertificateToken>();
			encapsulatedCerts = getCertificates(xPathQueryHolder.XPATH_ENCAPSULATED_X509_CERTIFICATE);
			keyInfoCerts = getCertificates(xPathQueryHolder.XPATH_KEY_INFO_X509_CERTIFICATE);
			timestampValidationDataCerts = getCertificates(xPathQueryHolder.XPATH_TSVD_ENCAPSULATED_X509_CERTIFICATE);
		}

		if (LOG.isInfoEnabled()) {
			LOG.info("+XAdESCertificateSource");
		}
	}

	/**
	 * @param xPathQuery XPath query
	 * @return
	 */
	private List<CertificateToken> getCertificates(final String xPathQuery) {

		final List<CertificateToken> list = new ArrayList<CertificateToken>();
		final NodeList nodeList = DSSXMLUtils.getNodeList(signatureElement, xPathQuery);
		for (int ii = 0; ii < nodeList.getLength(); ii++) {

			final Element certificateElement = (Element) nodeList.item(ii);

			final byte[] derEncoded = DSSUtils.base64Decode(certificateElement.getTextContent());
			final CertificateToken cert = DSSUtils.loadCertificate(derEncoded);
			final CertificateToken certToken = addCertificate(cert);
			if (!list.contains(certToken)) {

				final String idIdentifier = DSSXMLUtils.getIDIdentifier(certificateElement);
				certToken.setXmlId(idIdentifier);
				list.add(certToken);
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
	public List<CertificateToken> getEncapsulatedCertificates() throws DSSException {

		return encapsulatedCerts;
	}

	/**
	 * Returns the list of certificates included in "ds:KeyInfo/ds:X509Data/ds:X509Certificate" node
	 *
	 * @return list of X509Certificate(s)
	 */
	public List<CertificateToken> getKeyInfoCertificates() throws DSSException {

		return keyInfoCerts;
	}

	/**
	 * Returns the list of certificates included in "xades141:TimeStampValidationData/xades132:CertificateValues" node
	 *
	 * @return
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	public List<CertificateToken> getTimestampCertificates() throws DSSException {

		return timestampValidationDataCerts;
	}
}
