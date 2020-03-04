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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.IssuerSerialInfo;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.xades.DSSXMLUtils;
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
	 * The default constructor for XAdESCertificateSource. All certificates are
	 * extracted during instantiation.
	 *
	 * @param signatureElement
	 *                         {@code Element} that contains an XML signature
	 * @param xadesPaths
	 *                         adapted {@code XAdESPaths}
	 * @param certificatePool
	 *                         {@code CertificatePool} to use to declare the found
	 *                         certificates
	 */
	public XAdESCertificateSource(final Element signatureElement, final XAdESPaths xadesPaths, final CertificatePool certificatePool) {
		super(certificatePool);
		Objects.requireNonNull(signatureElement, "Element signature must not be null");
		Objects.requireNonNull(xadesPaths, "XAdESPaths must not be null");

		this.signatureElement = signatureElement;
		this.xadesPaths = xadesPaths;

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
			keyInfoCertificates = getCertificates(XMLDSigPaths.KEY_INFO_X509_CERTIFICATE_PATH);
		}
		return keyInfoCertificates;
	}

	@Override
	public List<CertificateToken> getCertificateValues() {
		if (certificateValues == null) {
			certificateValues = getCertificates(xadesPaths.getEncapsulatedCertificateValuesPath());
		}
		return certificateValues;
	}

	@Override
	public List<CertificateToken> getAttrAuthoritiesCertValues() {
		if (attrAuthoritiesCertValues == null) {
			attrAuthoritiesCertValues = getCertificates(xadesPaths.getEncapsulatedAttrAuthoritiesCertValuesPath());
		}
		return attrAuthoritiesCertValues;
	}

	@Override
	public List<CertificateToken> getTimeStampValidationDataCertValues() {
		if (timeStampValidationDataCertValues == null) {
			timeStampValidationDataCertValues = getCertificates(xadesPaths.getEncapsulatedTimeStampValidationDataCertValuesPath());
		}
		return timeStampValidationDataCertValues;
	}

	@Override
	public List<CertificateToken> getSignedDataCertificates() {
		// not applicable for XAdES
		return Collections.emptyList();
	}

	/**
	 * This method extracts certificates from the given xpath query
	 * 
	 * @param xPathQuery
	 *                   XPath query
	 * @return a list of {@code CertificateToken}
	 */
	private List<CertificateToken> getCertificates(final String xPathQuery) {
		if (xPathQuery == null) {
			return Collections.emptyList();
		}
		final List<CertificateToken> list = new ArrayList<>();
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
			signingCertificateValues = new ArrayList<>();
			NodeList certNodeList = DomUtils.getNodeList(signatureElement, xadesPaths.getSigningCertificatePath());
			if (certNodeList != null) {
				signingCertificateValues.addAll(extractXAdESCertsV1(certNodeList, CertificateRefOrigin.SIGNING_CERTIFICATE));
			}
			String signingCertificateV2Path = xadesPaths.getSigningCertificateV2Path();
			if (signingCertificateV2Path != null) {
				certNodeList = DomUtils.getNodeList(signatureElement, signingCertificateV2Path);
				if (certNodeList != null) {
					signingCertificateValues.addAll(extractXAdESCertsV2(certNodeList, CertificateRefOrigin.SIGNING_CERTIFICATE));
				}
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
			completeCertificateRefs = new ArrayList<>();
			NodeList certNodeList = DomUtils.getNodeList(signatureElement, xadesPaths.getCompleteCertificateRefsCertPath());
			if (certNodeList != null) {
				completeCertificateRefs.addAll(extractXAdESCertsV1(certNodeList, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS));
			}
			String completeCertificateRefsV2CertPath = xadesPaths.getCompleteCertificateRefsV2CertPath();
			if (completeCertificateRefsV2CertPath != null) {
				certNodeList = DomUtils.getNodeList(signatureElement, completeCertificateRefsV2CertPath);
				if (certNodeList != null) {
					completeCertificateRefs.addAll(extractXAdESCertsV2(certNodeList, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS));
				}
			}
		}
		return completeCertificateRefs;
	}

	@Override
	public List<CertificateRef> getAttributeCertificateRefs() {
		if (attributeCertificateRefs == null) {
			attributeCertificateRefs = new ArrayList<>();
			String attributeCertificateRefsCertPath = xadesPaths.getAttributeCertificateRefsCertPath();
			if (attributeCertificateRefsCertPath != null) {
				NodeList certNodeList = DomUtils.getNodeList(signatureElement, attributeCertificateRefsCertPath);
				if (certNodeList != null) {
					attributeCertificateRefs.addAll(extractXAdESCertsV1(certNodeList, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS));
				}
			}
			String attributeCertificateRefsV2CertPath = xadesPaths.getAttributeCertificateRefsV2CertPath();
			if (attributeCertificateRefsV2CertPath != null) {
				NodeList certNodeList = DomUtils.getNodeList(signatureElement, attributeCertificateRefsV2CertPath);
				if (certNodeList != null) {
					attributeCertificateRefs.addAll(extractXAdESCertsV2(certNodeList, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS));
				}
			}
		}
		return attributeCertificateRefs;
	}

	private List<CertificateRef> extractXAdESCertsV1(NodeList certNodeList, CertificateRefOrigin location) {
		List<CertificateRef> result = new ArrayList<>();
		for (int i = 0; i < certNodeList.getLength(); i++) {
			final Element cert = (Element) certNodeList.item(i);
			if (cert != null) {
				Digest certDigest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(cert, xadesPaths.getCurrentCertDigest()));
				if (certDigest != null) {
					CertificateRef certRef = new CertificateRef();
					certRef.setCertDigest(certDigest);
					certRef.setIssuerInfo(getIssuerV1(cert));
					certRef.setOrigin(location);
					result.add(certRef);
				}
			}
		}
		return result;
	}

	private List<CertificateRef> extractXAdESCertsV2(NodeList certNodeList, CertificateRefOrigin location) {
		List<CertificateRef> result = new ArrayList<>();
		for (int i = 0; i < certNodeList.getLength(); i++) {
			final Element cert = (Element) certNodeList.item(i);
			if (cert != null) {
				Digest certDigest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(cert, xadesPaths.getCurrentCertDigest()));
				if (certDigest != null) {
					CertificateRef certRef = new CertificateRef();
					certRef.setCertDigest(certDigest);
					certRef.setIssuerInfo(getIssuerV2(cert));
					certRef.setOrigin(location);
					result.add(certRef);
				}
			}
		}
		return result;
	}

	private IssuerSerialInfo getIssuerV1(Element certElement) {
		IssuerSerialInfo issuerInfo = new IssuerSerialInfo();

		final Element issuerNameEl = DomUtils.getElement(certElement, xadesPaths.getCurrentIssuerSerialIssuerNamePath());
		if (issuerNameEl != null) {
			issuerInfo.setIssuerName(DSSUtils.getX500PrincipalOrNull(issuerNameEl.getTextContent()));
		}

		final Element serialNumberEl = DomUtils.getElement(certElement, xadesPaths.getCurrentIssuerSerialSerialNumberPath());
		if (serialNumberEl != null) {
			final String serialNumberText = serialNumberEl.getTextContent();
			issuerInfo.setSerialNumber(new BigInteger(serialNumberText.trim()));
		}

		return issuerInfo;
	}
	
	private IssuerSerialInfo getIssuerV2(Element certElement) {
		final Element issuerSerialV2Element = DomUtils.getElement(certElement, xadesPaths.getCurrentIssuerSerialV2Path());
		if (issuerSerialV2Element == null) {
			// Tag issuerSerialV2 is optional
			return null;
		}

		final String textContent = issuerSerialV2Element.getTextContent();
		return getIssuerInfo(DSSASN1Utils.getIssuerSerial(Utils.fromBase64(textContent)));
	}

}
