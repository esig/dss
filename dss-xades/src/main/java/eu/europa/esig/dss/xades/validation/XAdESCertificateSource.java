/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigPath;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.SignerIdentifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.security.PublicKey;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * This class provides the mechanism to retrieve certificates contained in a XAdES signature.
 *
 */
@SuppressWarnings("serial")
public class XAdESCertificateSource extends SignatureCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESCertificateSource.class);

	/** The Signature element */
	private final Element signatureElement;

	/** Contains a list of XAdES path corresponding to the signature */
	private final XAdESPath xadesPaths;
	
	/**
	 * The default constructor for XAdESCertificateSource. All certificates are
	 * extracted during instantiation.
	 *
	 * @param signatureElement
	 *                         {@code Element} that contains an XML signature
	 * @param xadesPaths
	 *                         adapted {@code XAdESPaths}
	 */
	public XAdESCertificateSource(final Element signatureElement, final XAdESPath xadesPaths) {
		Objects.requireNonNull(signatureElement, "Element signature must not be null");
		Objects.requireNonNull(xadesPaths, "XAdESPaths must not be null");

		this.signatureElement = signatureElement;
		this.xadesPaths = xadesPaths;

		// init
		extractCertificates(XMLDSigPath.KEY_INFO_X509_CERTIFICATE_PATH, CertificateOrigin.KEY_INFO);
		extractCertificates(xadesPaths.getEncapsulatedCertificateValuesPath(), CertificateOrigin.CERTIFICATE_VALUES);
		extractCertificates(xadesPaths.getEncapsulatedAttrAuthoritiesCertValuesPath(), CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES);
		extractCertificates(xadesPaths.getEncapsulatedTimeStampValidationDataCertValuesPath(), CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
		extractCertificates(xadesPaths.getEncapsulatedAnyValidationDataCertValuesPath(), CertificateOrigin.ANY_VALIDATION_DATA);

		extractCertificateRefs(xadesPaths.getSigningCertificateChildren(), xadesPaths.getSigningCertificateV2Children(),
				CertificateRefOrigin.SIGNING_CERTIFICATE);
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
			String base64EncodedCertificate = certificateElement.getTextContent();
			try {
				final byte[] derEncoded = Utils.fromBase64(base64EncodedCertificate);
				final CertificateToken cert = DSSUtils.loadCertificate(derEncoded);
				addCertificate(cert, origin);

			} catch (Exception e) {
				LOG.warn("Unable to parse certificate '{}' : {}", certificateElement.getTextContent(), e.getMessage(), e);
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
				addCertificateRef(certificateRef, origin);
			}
		}
	}

	private void extractXAdESCertsV2(NodeList certNodeList, CertificateRefOrigin origin) {
		for (int i = 0; i < certNodeList.getLength(); i++) {
			final Element certRefElement = (Element) certNodeList.item(i);
			final CertificateRef certificateRef = XAdESCertificateRefExtractionUtils.createCertificateRefFromV2(certRefElement, xadesPaths);
			if (certificateRef != null) {
				addCertificateRef(certificateRef, origin);
			}
		}
	}
	
	@Override
	protected CandidatesForSigningCertificate extractCandidatesForSigningCertificate(
			CertificateSource signingCertificateSource) {
		CandidatesForSigningCertificate candidatesForSigningCertificate = new CandidatesForSigningCertificate();
		
		/*
		 * 5.1.4.1 XAdES processing
		 *
		 * Candidates for the signing certificate extracted from ds:KeyInfo
		 * element shall be checked against all references present in the
		 * ds:SigningCertificate property, if present, since one of these references
		 * shall be a reference to the signing certificate.
		 */
		for (final CertificateToken certificateToken : getKeyInfoCertificates()) {
			candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
		}
		
		// if KeyInfo does not contain certificates,
		// check other certificates embedded into the signature
		if (candidatesForSigningCertificate.isEmpty()) {
			PublicKey publicKey = DSSXMLUtils.getKeyInfoSigningCertificatePublicKey(signatureElement);
			if (publicKey != null) {
				
				// try to find out the signing certificate token by provided public key
				Set<CertificateToken> certsByPublicKey = getByPublicKey(publicKey);
				
				if (Utils.isCollectionNotEmpty(certsByPublicKey)) {
					for (CertificateToken certificateToken : certsByPublicKey) {
						candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
					}
				} else {
					// process public key only if no certificates found
					candidatesForSigningCertificate.add(new CertificateValidity(publicKey));
				}
				
			} else {
				// Add all found certificates
				for (CertificateToken certificateToken : getCertificates()) {
					candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
				}
			}
					
		}

		if (signingCertificateSource != null) {
			resolveFromSource(signingCertificateSource, candidatesForSigningCertificate);
		}
		
		checkCandidatesAgainstSigningCertificateRef(candidatesForSigningCertificate);

		return candidatesForSigningCertificate;
	}

	private void resolveFromSource(CertificateSource certificateSource, CandidatesForSigningCertificate candidatesForSigningCertificate) {
		List<CertificateRef> signingCertificateRefs = getSigningCertificateRefs();
		if (Utils.isCollectionNotEmpty(signingCertificateRefs)) {
			for (CertificateRef certificateRef : signingCertificateRefs) {
				resolveForReference(certificateRef, certificateSource, candidatesForSigningCertificate);
			}

		} else {
			List<CertificateToken> certificates = certificateSource.getCertificates();
			LOG.debug("No signing certificate reference found. " +
					"Resolve all {} certificates from the provided certificate source as signing candidates.", certificates.size());
			for (CertificateToken certCandidate : certificates) {
				candidatesForSigningCertificate.add(new CertificateValidity(certCandidate));
			}
		}
	}

	private void resolveForReference(CertificateRef certificateRef, CertificateSource certificateSource,
									 CandidatesForSigningCertificate candidatesForSigningCertificate) {
		SignerIdentifier signerIdentifier = certificateRef.getCertificateIdentifier();
		if (signerIdentifier != null) {
			Set<CertificateToken> certificatesByIdentifier = certificateSource
					.getBySignerIdentifier(signerIdentifier);
			if (Utils.isCollectionNotEmpty(certificatesByIdentifier)) {
				LOG.debug("Resolved certificate by certificate identifier");
				for (CertificateToken certCandidate : certificatesByIdentifier) {
					candidatesForSigningCertificate.add(new CertificateValidity(certCandidate));
				}
				return;
			}
		}

		Digest certDigest = certificateRef.getCertDigest();
		if (certDigest != null) {
			Set<CertificateToken> certificatesByDigest = certificateSource.getByCertificateDigest(certDigest);
			if (Utils.isCollectionNotEmpty(certificatesByDigest)) {
				LOG.debug("Resolved certificate by digest");
				for (CertificateToken certCandidate : certificatesByDigest) {
					candidatesForSigningCertificate.add(new CertificateValidity(certCandidate));
				}
			}
		}
	}

	/**
	 * This method checks the protection of the certificates included within the signature (XAdES: KeyInfo) against the
	 * substitution attack.
	 */
	private void checkCandidatesAgainstSigningCertificateRef(final CandidatesForSigningCertificate candidates) {
		final List<CertificateRef> potentialSigningCertificates = getSigningCertificateRefs();
		if (Utils.isCollectionNotEmpty(potentialSigningCertificates)) {
			// first reference shall be a reference to a signing certificate
			final CertificateRef signingCert = potentialSigningCertificates.get(0);
			
			CertificateValidity bestCertificateValidity = null;
			// check all certificates against the signingCert ref and find the best one
			final List<CertificateValidity> certificateValidityList = candidates.getCertificateValidityList();
			for (final CertificateValidity certificateValidity : certificateValidityList) {
				if (isValid(certificateValidity, signingCert)) {
					bestCertificateValidity = certificateValidity;
				}
			}
			if (bestCertificateValidity != null) {
				candidates.setTheCertificateValidity(bestCertificateValidity);
			}
		}
	}

	private boolean isValid(CertificateValidity certificateValidity, CertificateRef signingCert) {
		certificateValidity.setDigestPresent(signingCert.getCertDigest() != null);
		certificateValidity.setIssuerSerialPresent(signingCert.getCertificateIdentifier() != null);

		CertificateToken certificateToken = certificateValidity.getCertificateToken();
		if (certificateToken != null) {
			certificateValidity.setDigestEqual(certificateMatcher.matchByDigest(certificateToken, signingCert));
			certificateValidity.setSerialNumberEqual(certificateMatcher.matchBySerialNumber(certificateToken, signingCert));
			certificateValidity.setDistinguishedNameEqual(certificateMatcher.matchByIssuerName(certificateToken, signingCert));
		}
		return certificateValidity.isValid();
	}

}
