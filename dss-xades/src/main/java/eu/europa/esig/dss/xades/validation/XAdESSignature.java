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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.xml.transform.stream.StreamSource;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.TokenIdentifier;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CRLRef;
import eu.europa.esig.dss.validation.CandidatesForSigningCertificate;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.CertificateValidity;
import eu.europa.esig.dss.validation.CertifiedRole;
import eu.europa.esig.dss.validation.CommitmentType;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.DigestMatcherType;
import eu.europa.esig.dss.validation.OCSPRef;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.TimestampInclude;
import eu.europa.esig.dss.validation.TimestampReference;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.TimestampedObjectType;
import eu.europa.esig.dss.x509.ArchiveTimestampType;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.SantuarioInitializer;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * Parse an XAdES signature structure. Note that for each signature to be validated a new instance of this object must
 * be created.
 *
 */
public class XAdESSignature extends DefaultAdvancedSignature {
	
	private static final long serialVersionUID = -2639858392612722185L;

	private static final Logger LOG = LoggerFactory.getLogger(XAdESSignature.class);

	/**
	 * This array contains all the XAdES signatures levels TODO: do not return redundant levels.
	 */
	private static SignatureLevel[] signatureLevels = new SignatureLevel[] { SignatureLevel.XML_NOT_ETSI, SignatureLevel.XAdES_BASELINE_B,
			SignatureLevel.XAdES_BASELINE_T, SignatureLevel.XAdES_C, SignatureLevel.XAdES_X, SignatureLevel.XAdES_BASELINE_LT,
			SignatureLevel.XAdES_BASELINE_LTA };

	/**
	 * This variable contains the list of {@code XPathQueryHolder} adapted to the specific signature schema.
	 */
	private final List<XPathQueryHolder> xPathQueryHolders;

	/**
	 * This variable contains the XPathQueryHolder adapted to the signature schema.
	 */
	protected XPathQueryHolder xPathQueryHolder;

	private final Element signatureElement;

	/**
	 * Indicates the id of the signature. If not existing this attribute is auto calculated.
	 */
	private String signatureId;

	private XAdESCertificateSource certificatesSource;

	/**
	 * This variable contains all references found within the signature. They are extracted when the method
	 * {@code checkSignatureIntegrity} is called.
	 */
	private transient List<Reference> references = new ArrayList<Reference>();

	/**
	 * Cached list of the Signing Certificate Timestamp References.
	 */
	private List<TimestampReference> signingCertificateTimestampReferences;

	static {

		SantuarioInitializer.init();

		/**
		 * Adds the support of ECDSA_RIPEMD160 for XML signature. Used by AT. The BC provider must be previously added.
		 */
		// final JCEMapper.Algorithm algorithm = new JCEMapper.Algorithm("",
		// SignatureAlgorithm.ECDSA_RIPEMD160.getJCEId(), "Signature");
		// final String xmlId = SignatureAlgorithm.ECDSA_RIPEMD160.getXMLId();
		// JCEMapper.register(xmlId, algorithm);
		// try {
		// org.apache.xml.security.algorithms.SignatureAlgorithm.register(xmlId,
		// SignatureECDSARIPEMD160.class);
		// } catch (Exception e) {
		// LOG.error("ECDSA_RIPEMD160 algorithm initialisation failed.", e);
		// }

		/**
		 * Adds the support of not standard algorithm name: http://www.w3.org/2001/04/xmldsig-more/rsa-ripemd160. Used
		 * by some AT signature providers. The BC
		 * provider must be previously added.
		 */

		final JCEMapper.Algorithm notStandardAlgorithm = new JCEMapper.Algorithm("", SignatureAlgorithm.RSA_RIPEMD160.getJCEId(), "Signature");
		JCEMapper.register(SignatureRSARIPEMD160AT.XML_ID, notStandardAlgorithm);
		try {
			org.apache.xml.security.algorithms.SignatureAlgorithm.register(SignatureRSARIPEMD160AT.XML_ID, SignatureRSARIPEMD160AT.class);
		} catch (Exception e) {
			LOG.error("ECDSA_RIPEMD160AT algorithm initialisation failed.", e);
		}

	}

	/**
	 * This constructor is used when creating the signature. The default {@code XPathQueryHolder} is set.
	 *
	 * @param signatureElement
	 *            the signature DOM element
	 */
	public XAdESSignature(final Element signatureElement) {
		this(signatureElement, Arrays.asList(new XPathQueryHolder()), new CertificatePool());
	}

	/**
	 * The default constructor for XAdESSignature.
	 *
	 * @param signatureElement
	 *            the signature DOM element
	 * @param xPathQueryHolders
	 *            List of {@code XPathQueryHolder} to use when handling signature
	 * @param certPool
	 *            the certificate pool (can be null)
	 */
	public XAdESSignature(final Element signatureElement, final List<XPathQueryHolder> xPathQueryHolders, final CertificatePool certPool) {
		super(certPool);
		if (signatureElement == null) {
			throw new NullPointerException("signatureElement");
		}
		this.signatureElement = signatureElement;
		this.xPathQueryHolders = xPathQueryHolders;
		initialiseSettings();
	}

	/**
	 * This method is called when creating a new instance of the {@code XAdESSignature} with unknown schema.
	 */
	private void initialiseSettings() {

		recursiveNamespaceBrowser(signatureElement);
		if (xPathQueryHolder == null) {

			LOG.warn("There is no suitable XPathQueryHolder to manage the signature. The default one will be used.");
			xPathQueryHolder = new XPathQueryHolder();
		}
	}

	/**
	 * This method sets the namespace which will determinate the {@code XPathQueryHolder} to use. The content of the
	 * Transform element is ignored.
	 *
	 * @param element
	 */
	public void recursiveNamespaceBrowser(final Element element) {

		for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {

			final Node node = element.getChildNodes().item(ii);
			if (node.getNodeType() == Node.ELEMENT_NODE) {

				final Element childElement = (Element) node;
				final String namespaceURI = childElement.getNamespaceURI();
				final String localName = childElement.getLocalName();
				if (XPathQueryHolder.XMLE_TRANSFORM.equals(localName) && javax.xml.crypto.dsig.XMLSignature.XMLNS.equals(namespaceURI)) {
					continue;
				} else if (XPathQueryHolder.XMLE_QUALIFYING_PROPERTIES.equals(localName)) {

					setXPathQueryHolder(namespaceURI);
					return;
				}
				recursiveNamespaceBrowser(childElement);
			}
		}
	}

	private void setXPathQueryHolder(final String namespaceURI) {

		for (final XPathQueryHolder xPathQueryHolder : xPathQueryHolders) {

			final boolean canUseThisXPathQueryHolder = xPathQueryHolder.canUseThisXPathQueryHolder(namespaceURI);
			if (canUseThisXPathQueryHolder) {

				this.xPathQueryHolder = xPathQueryHolder;
			}
		}
	}

	/**
	 * This getter returns the {@code XPathQueryHolder}
	 *
	 * @return
	 */
	public XPathQueryHolder getXPathQueryHolder() {
		return xPathQueryHolder;
	}

	/**
	 * Returns the w3c.dom encapsulated signature element.
	 *
	 * @return the signatureElement
	 */
	public Element getSignatureElement() {
		return signatureElement;
	}

	@Override
	public SignatureForm getSignatureForm() {
		return SignatureForm.XAdES;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		final SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
		if (signatureAlgorithm == null) {
			return null;
		}
		return signatureAlgorithm.getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		final SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
		if (signatureAlgorithm == null) {
			return null;
		}
		return signatureAlgorithm.getDigestAlgorithm();
	}

	@Override
	public MaskGenerationFunction getMaskGenerationFunction() {
		final SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
		if (signatureAlgorithm == null) {
			return null;
		}
		return signatureAlgorithm.getMaskGenerationFunction();
	}

	@Override
	public SignatureAlgorithm getSignatureAlgorithm() {
		final String xmlName = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_METHOD).getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
		return SignatureAlgorithm.forXML(xmlName, null);
	}

	@Override
	public XAdESCertificateSource getCertificateSource() {
		if (certificatesSource == null) {
			certificatesSource = new XAdESCertificateSource(signatureElement, xPathQueryHolder, certPool);
		}
		return certificatesSource;
	}

	/**
	 * This method resets the source of certificates. It must be called when any certificate is added to the KeyInfo or
	 * CertificateValues.
	 */
	public void resetCertificateSource() {
		certificatesSource = null;
	}

	@Override
	public OfflineCRLSource getCRLSource() {
		if (offlineCRLSource == null) {
			offlineCRLSource = new XAdESCRLSource(signatureElement, xPathQueryHolder);
		}
		return offlineCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {
		if (offlineOCSPSource == null) {
			offlineOCSPSource = new XAdESOCSPSource(signatureElement, xPathQueryHolder);
		}
		return offlineOCSPSource;
	}

	/**
	 * This method resets the sources of the revocation data. It must be called when -LT level is created.
	 */
	public void resetRevocationSources() {
		offlineCRLSource = null;
		offlineOCSPSource = null;
	}

	public void resetTimestamps() {
		signatureTimestamps = null;
		contentTimestamps = null;
		archiveTimestamps = null;
		sigAndRefsTimestamps = null;
		refsOnlyTimestamps = null;
	}

	@Override
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate() {
		if (candidatesForSigningCertificate != null) {
			return candidatesForSigningCertificate;
		}
		candidatesForSigningCertificate = new CandidatesForSigningCertificate();
		/**
		 * 5.1.4.1 XAdES processing<br>
		 * <i>Candidates for the signing certificate extracted from ds:KeyInfo element</i> shall be checked against all
		 * references present in the
		 * ds:SigningCertificate property, if present, since one of these references shall be a reference to the signing
		 * certificate.
		 */
		final XAdESCertificateSource certSource = getCertificateSource();
		for (final CertificateToken certificateToken : certSource.getKeyInfoCertificates()) {
			final CertificateValidity certificateValidity = new CertificateValidity(certificateToken);
			candidatesForSigningCertificate.add(certificateValidity);
		}
		return candidatesForSigningCertificate;
	}

	@Override
	public void checkSigningCertificate() {

		final CandidatesForSigningCertificate candidates = getCandidatesForSigningCertificate();
		/**
		 * The ../SignedProperties/SignedSignatureProperties/SigningCertificate element MAY contain references and
		 * digests values of other certificates (that
		 * MAY form a chain up to the point of trust).
		 */
		boolean isEn319132 = false;
		NodeList list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNING_CERTIFICATE_CERT);
		int length = list.getLength();
		if (length == 0) {
			list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNING_CERTIFICATE_CERT_V2);
			length = list.getLength();
			isEn319132 = true;
		}

		// This Map contains the list of the references to the certificate which
		// were already checked and which correspond to a certificate.
		Map<Element, Boolean> alreadyProcessedElements = new HashMap<Element, Boolean>();

		final List<CertificateValidity> certificateValidityList = candidates.getCertificateValidityList();
		for (final CertificateValidity certificateValidity : certificateValidityList) {

			final CertificateToken certificateToken = certificateValidity.getCertificateToken();
			for (int ii = 0; ii < length; ii++) {

				certificateValidity.setAttributePresent(true);
				final Element element = (Element) list.item(ii);
				if (alreadyProcessedElements.containsKey(element)) {
					continue;
				}
				final Element certDigestElement = DomUtils.getElement(element, xPathQueryHolder.XPATH__CERT_DIGEST);
				certificateValidity.setDigestPresent(certDigestElement != null);

				final Element digestMethodElement = DomUtils.getElement(certDigestElement, xPathQueryHolder.XPATH__DIGEST_METHOD);
				if (digestMethodElement == null) {
					continue;
				}
				final String xmlAlgorithmName = digestMethodElement.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
				// The default algorithm is used in case of bad encoded
				// algorithm name
				final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(xmlAlgorithmName, DigestAlgorithm.SHA1);

				final Element digestValueElement = DomUtils.getElement(element, xPathQueryHolder.XPATH__CERT_DIGEST_DIGEST_VALUE);
				if (digestValueElement == null) {
					continue;
				}
				// That must be a binary comparison
				final byte[] storedBase64DigestValue = Utils.fromBase64(digestValueElement.getTextContent());

				/**
				 * Step 1:<br>
				 * Take the first child of the property and check that the content of ds:DigestValue matches the result
				 * of digesting <i>the candidate for</i>
				 * the signing certificate with the algorithm indicated in ds:DigestMethod. If they do not match, take
				 * the next child and repeat this step until
				 * a matching child element has been found or all children of the element have been checked. If they do
				 * match, continue with step 2. If the last
				 * element is reached without finding any match, the validation of this property shall be taken as
				 * failed and INVALID/FORMAT_FAILURE is
				 * returned.
				 */
				final byte[] digest = certificateToken.getDigest(digestAlgorithm);
				boolean digestEqual = Arrays.equals(digest, storedBase64DigestValue);
				certificateValidity.setDigestEqual(digestEqual);

				if (digestEqual) {
					BigInteger serialNumber = null;
					X500Principal issuerName = null;
					if (isEn319132) {
						final Element issuerSerialV2Element = DomUtils.getElement(element, xPathQueryHolder.XPATH__X509_ISSUER_V2);
						// Tag issuerSerialV2 is optional
						if (issuerSerialV2Element != null) {
							final String textContent = issuerSerialV2Element.getTextContent();
							try (ASN1InputStream is = new ASN1InputStream(Utils.fromBase64(textContent))) {
								ASN1Sequence seq = (ASN1Sequence) is.readObject();
								ASN1Sequence obj = (ASN1Sequence) seq.getObjectAt(0);
								GeneralName name = GeneralName.getInstance(obj.getObjectAt(0));
								if (name != null) {
									issuerName = new X500Principal(name.getName().toASN1Primitive().getEncoded());
								}

								ASN1Integer serial = (ASN1Integer) seq.getObjectAt(1);
								if (serial != null) {
									serialNumber = serial.getValue();
								}
							} catch (Exception e) {
								LOG.error("Unable to decode textContent '" + textContent + "' : " + e.getMessage(), e);
							}
						}
					} else {
						final Element issuerNameEl = DomUtils.getElement(element, xPathQueryHolder.XPATH__X509_ISSUER_NAME);

						issuerName = DSSUtils.getX500PrincipalOrNull(issuerNameEl.getTextContent());

						final Element serialNumberEl = DomUtils.getElement(element, xPathQueryHolder.XPATH__X509_SERIAL_NUMBER);
						final String serialNumberText = serialNumberEl.getTextContent();
						// serial number can contain leading and trailing whitespace.
						serialNumber = new BigInteger(serialNumberText.trim());
					}
					final X500Principal candidateIssuerName = certificateToken.getIssuerX500Principal();

					final boolean issuerNameMatches = DSSUtils.x500PrincipalAreEquals(candidateIssuerName, issuerName);
					certificateValidity.setDistinguishedNameEqual(issuerNameMatches);
					if (!issuerNameMatches) {
						final String c14nCandidateIssuerName = candidateIssuerName.getName(X500Principal.CANONICAL);
						LOG.info("candidateIssuerName : {}", c14nCandidateIssuerName);
						final String c14nIssuerName = issuerName == null ? "" : issuerName.getName(X500Principal.CANONICAL);
						LOG.info("issuerName : {}", c14nIssuerName);
					}

					final BigInteger candidateSerialNumber = certificateToken.getSerialNumber();
					final boolean serialNumberMatches = candidateSerialNumber.equals(serialNumber);
					certificateValidity.setSerialNumberEqual(serialNumberMatches);

					// The certificate was identified
					alreadyProcessedElements.put(element, true);
					// If the signing certificate is not set yet then it must be
					// done now. Actually if the signature is tempered then the
					// method checkSignatureIntegrity cannot set the signing
					// certificate.
					if (candidates.getTheCertificateValidity() == null) {
						candidates.setTheCertificateValidity(certificateValidity);
					}
					break;
				}
			}
		}
	}

	@Override
	public Date getSigningTime() {

		final Element signingTimeEl = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNING_TIME);
		if (signingTimeEl == null) {
			return null;
		}
		final String text = signingTimeEl.getTextContent();
		return DomUtils.getDate(text);
	}

	@Override
	public void checkSignaturePolicy(SignaturePolicyProvider signaturePolicyProvider) {
		final Element policyIdentifier = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER);
		if (policyIdentifier != null) {
			// There is a policy
			final Element policyId = DomUtils.getElement(policyIdentifier, xPathQueryHolder.XPATH__POLICY_ID);
			if (policyId != null) {
				// Explicit policy
				String policyUrlString = null;
				String policyIdString = policyId.getTextContent();
				if (Utils.isStringNotEmpty(policyIdString)) {
					policyIdString = policyIdString.replaceAll("\n", "");
					policyIdString = policyIdString.trim();
					if (DSSXMLUtils.isOid(policyIdString)) {
						// urn:oid:1.2.3 --> 1.2.3
						policyIdString = DSSXMLUtils.getOidCode(policyIdString);
					} else {
						policyUrlString = policyIdString;
					}
				}
				signaturePolicy = new SignaturePolicy(policyIdString);
				final Node policyDigestMethod = DomUtils.getNode(policyIdentifier, xPathQueryHolder.XPATH__POLICY_DIGEST_METHOD);
				final String policyDigestMethodString = policyDigestMethod.getTextContent();
				if (Utils.isStringNotEmpty(policyDigestMethodString)) {
					final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(policyDigestMethodString);
					signaturePolicy.setDigestAlgorithm(digestAlgorithm);
				}
				final Element policyDigestValue = DomUtils.getElement(policyIdentifier, xPathQueryHolder.XPATH__POLICY_DIGEST_VALUE);
				final String digestValue = policyDigestValue.getTextContent().trim();
				signaturePolicy.setDigestValue(digestValue);
				final Element policyUrl = DomUtils.getElement(policyIdentifier, xPathQueryHolder.XPATH__POLICY_SPURI);
				if (policyUrl != null) {
					policyUrlString = policyUrl.getTextContent().trim();
				}
				final Element policyDescription = DomUtils.getElement(policyIdentifier, xPathQueryHolder.XPATH__POLICY_DESCRIPTION);
				if (policyDescription != null && Utils.isStringNotEmpty(policyDescription.getTextContent())) {
					signaturePolicy.setDescription(policyDescription.getTextContent());
				}
				signaturePolicy.setUrl(policyUrlString);
				signaturePolicy.setPolicyContent(signaturePolicyProvider.getSignaturePolicy(policyIdString, policyUrlString));
			} else {
				// Implicit policy
				final Element signaturePolicyImplied = DomUtils.getElement(policyIdentifier, xPathQueryHolder.XPATH__SIGNATURE_POLICY_IMPLIED);
				if (signaturePolicyImplied != null) {
					signaturePolicy = new SignaturePolicy();
				}
			}
		}
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {

		NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_PRODUCTION_PLACE);
		if ((nodeList.getLength() == 0) || (nodeList.item(0) == null)) {
			nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_PRODUCTION_PLACE_V2);
			if ((nodeList.getLength() == 0) || (nodeList.item(0) == null)) {
				return null;
			}
		}
		final SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
		final NodeList list = nodeList.item(0).getChildNodes();
		for (int ii = 0; ii < list.getLength(); ii++) {

			final Node item = list.item(ii);
			final String name = item.getLocalName();
			final String nodeValue = item.getTextContent();
			if (XPathQueryHolder.XMLE_CITY.equals(name)) {

				signatureProductionPlace.setCity(nodeValue);
			} else if (XPathQueryHolder.XMLE_STATE_OR_PROVINCE.equals(name)) {

				signatureProductionPlace.setStateOrProvince(nodeValue);
			} else if (XPathQueryHolder.XMLE_POSTAL_CODE.equals(name)) {

				signatureProductionPlace.setPostalCode(nodeValue);
			} else if (XPathQueryHolder.XMLE_COUNTRY_NAME.equals(name)) {

				signatureProductionPlace.setCountryName(nodeValue);
			} else if (XPathQueryHolder.XMLE_STREET_ADDRESS.equals(name)) {

				signatureProductionPlace.setStreetAddress(nodeValue);
			}
		}
		return signatureProductionPlace;
	}

	@Override
	public String[] getClaimedSignerRoles() {

		NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CLAIMED_ROLE);
		if (nodeList.getLength() == 0) {
			nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CLAIMED_ROLE_V2);
			if (nodeList.getLength() == 0) {
				return null;
			}
		}
		final String[] roles = new String[nodeList.getLength()];
		for (int ii = 0; ii < nodeList.getLength(); ii++) {

			roles[ii] = nodeList.item(ii).getTextContent();
		}
		return roles;
	}

	@Override
	public List<CertifiedRole> getCertifiedSignerRoles() {
		/**
		 * <!-- Start EncapsulatedPKIDataType-->
		 * <xsd:element name="EncapsulatedPKIData" type="EncapsulatedPKIDataType"/>
		 * <xsd:complexType name="EncapsulatedPKIDataType">
		 * <xsd:simpleContent>
		 * <xsd:extension base="xsd:base-64Binary">
		 * <xsd:attribute name="Id" type="xsd:ID" use="optional"/>
		 * <xsd:attribute name="Encoding" type="xsd:anyURI" use="optional"/>
		 * </xsd:extension>
		 * </xsd:simpleContent>
		 * </xsd:complexType>
		 * <!-- End EncapsulatedPKIDataType -->
		 */
		NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CERTIFIED_ROLE);
		if (nodeList.getLength() == 0) {
			nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CERTIFIED_ROLE_V2);
			if (nodeList.getLength() == 0) {
				return null;
			}
		}
		final List<CertifiedRole> roles = new ArrayList<CertifiedRole>();
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			final Element certEl = (Element) nodeList.item(ii);
			final String textContent = certEl.getTextContent();
			CertifiedRole role = new CertifiedRole();
			role.setRole(textContent);
			if (!roles.contains(role)) {
				roles.add(role);
			}
		}
		return roles;
	}

	@Override
	public String getContentType() {
		return MimeType.XML.getMimeTypeString();
	}

	@Override
	public String getContentIdentifier() {
		return null;
	}

	@Override
	public String getContentHints() {
		return null;
	}

	/**
	 * This method creates {@code TimestampToken} based on provided parameters.
	 *
	 * @param timestampElement
	 *            contains the encapsulated timestamp
	 * @param timestampType
	 *            {@code TimestampType}
	 * @return {@code TimestampToken} of the given type
	 * @throws DSSException
	 */
	private TimestampToken makeTimestampToken(final Element timestampElement, final TimestampType timestampType) throws DSSException {

		final Element timestampTokenNode = DomUtils.getElement(timestampElement, xPathQueryHolder.XPATH__ENCAPSULATED_TIMESTAMP);
		if (timestampTokenNode == null) {
			LOG.warn("The timestamp {} cannot be extracted from the signature!", timestampType.name());
			return null;
		}
		TimestampToken timestampToken = null;
		try {
			timestampToken = new TimestampToken(Utils.fromBase64(timestampTokenNode.getTextContent()), timestampType, certPool);
		} catch (Exception e) {
			LOG.warn("Unable to build timestamp object '" + timestampTokenNode.getTextContent() + "' : ", e);
			return null;
		}
		timestampToken.setHashCode(timestampElement.hashCode());
		timestampToken.setCanonicalizationMethod(getTimestampCanonicalizationMethod(timestampElement));

		final NodeList timestampIncludes = DomUtils.getNodeList(timestampElement, xPathQueryHolder.XPATH__INCLUDE);
		if (timestampIncludes != null && timestampIncludes.getLength() > 0) {
			List<TimestampInclude> includes = new ArrayList<TimestampInclude>();
			for (int jj = 0; jj < timestampIncludes.getLength(); jj++) {
				final Element include = (Element) timestampIncludes.item(jj);
				final String uri = cleanURI(include.getAttribute("URI"));
				final String referencedData = include.getAttribute("referencedData");
				includes.add(new TimestampInclude(uri, Boolean.parseBoolean(referencedData)));
			}
			timestampToken.setTimestampIncludes(includes);
		}
		return timestampToken;
	}

	public Element getSignatureValue() {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_VALUE);
	}

	/**
	 * This method returns the list of ds:Object elements for the current signature element.
	 *
	 * @return
	 */
	public NodeList getObjects() {
		return DomUtils.getNodeList(signatureElement, XPathQueryHolder.XPATH_OBJECT);
	}

	public Element getCompleteCertificateRefs() {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS);
	}

	public Element getCompleteRevocationRefs() {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS);
	}

	public NodeList getSigAndRefsTimeStamp() {
		NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIG_AND_REFS_TIMESTAMP);
		if (nodeList == null || nodeList.getLength() == 0) {
			nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIG_AND_REFS_TIMESTAMP_V2);
		}
		return nodeList;
	}

	public Element getCertificateValues() {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_CERTIFICATE_VALUES);
	}

	public Element getRevocationValues() {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_REVOCATION_VALUES);
	}

	/**
	 * Checks the presence of ... segment in the signature, what is the proof -B profile existence
	 *
	 * @return true if B Profile is detected
	 */
	public boolean hasBProfile() {
		return DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_SIGNED_SIGNATURE_PROPERTIES);
	}

	/**
	 * Checks the presence of CompleteCertificateRefs and CompleteRevocationRefs segments in the signature, what is the
	 * proof -C profile existence
	 *
	 * @return true if C Profile is detected
	 */
	public boolean hasCProfile() {
		final boolean certRefs = DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS);
		final boolean revocationRefs = DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS);
		return certRefs || revocationRefs;
	}

	/**
	 * Checks the presence of SigAndRefsTimeStamp segment in the signature, what is the proof -X profile existence
	 *
	 * @return true if the -X extension is present
	 */
	public boolean hasXProfile() {
		return DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_SIG_AND_REFS_TIMESTAMP);
	}

	/**
	 * Utility method to add content timestamps.
	 *
	 * @param timestampTokens
	 *            List of timestamp tokens
	 * @param nodes
	 * @param timestampType
	 *            {@code TimestampType}
	 */
	public void addContentTimestamps(final List<TimestampToken> timestampTokens, final NodeList nodes, TimestampType timestampType) {
		for (int ii = 0; ii < nodes.getLength(); ii++) {
			final Node node = nodes.item(ii);
			if (node.getNodeType() != Node.ELEMENT_NODE) {
				continue;
			}
			final Element element = (Element) node;
			final TimestampToken timestampToken = makeTimestampToken(element, timestampType);
			if (timestampToken != null) {
				timestampTokens.add(timestampToken);
			}
		}
	}

	@Override
	public byte[] getContentTimestampData(final TimestampToken timestampToken) {
		final TimestampType timeStampType = timestampToken.getTimeStampType();
		if (timeStampType != TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP && timeStampType != TimestampType.ALL_DATA_OBJECTS_TIMESTAMP) {
			return null;
		}

		if (!checkTimestampTokenIncludes(timestampToken)) {
			throw new DSSException("The Included referencedData attribute is either not present or set to false!");
		}
		if (references.isEmpty()) {
			throw new DSSException("The method 'checkSignatureIntegrity' must be invoked first!");
		}

		final String canonicalizationMethod = timestampToken.getCanonicalizationMethod();
		final List<TimestampInclude> includes = timestampToken.getTimestampIncludes();

		try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

			for (final Reference reference : references) {
				if (isContentTimestampedReference(reference, timeStampType, includes)) {
					byte[] referencedBytes = reference.getReferencedBytes();
					if (Utils.isStringNotBlank(canonicalizationMethod) && DomUtils.isDOM(referencedBytes)) {
						referencedBytes = DSSXMLUtils.canonicalize(canonicalizationMethod, referencedBytes);
					}
					if (LOG.isTraceEnabled()) {
						LOG.trace("ReferencedBytes : {}", new String(referencedBytes));
					}
					outputStream.write(referencedBytes);
				}
			}

			byte[] byteArray = outputStream.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("IndividualDataObjectsTimestampData/AllDataObjectsTimestampData bytes: {}", new String(byteArray));
			}
			return byteArray;
		} catch (IOException | XMLSecurityException e) {
			throw new DSSException("Unable to extract IndividualDataObjectsTimestampData/AllDataObjectsTimestampData", e);
		}

	}

	private boolean isContentTimestampedReference(Reference reference, TimestampType timeStampType, List<TimestampInclude> includes) {
		if (timeStampType == TimestampType.ALL_DATA_OBJECTS_TIMESTAMP) {
			// All references are covered except the one referencing the SignedProperties
			return !isSignedProperties(reference);
		} else {
			for (TimestampInclude timestampInclude : includes) {
				String id = timestampInclude.getURI();
				if (reference.getId().equals(id)) {
					return true;
				}
			}
			return false;
		}
	}

	private List<TimestampReference> getSignatureTimestampedReferences() {

		final List<TimestampReference> references = new ArrayList<TimestampReference>();
		final TimestampReference signatureReference = getSignatureTimestampReference();
		references.add(signatureReference);
		final List<TimestampReference> signingCertificateTimestampReferences = getSigningCertificateTimestampReferences();
		references.addAll(signingCertificateTimestampReferences);
		return references;
	}

	private List<TimestampReference> getSigningCertificateTimestampReferences() {

		if (signingCertificateTimestampReferences == null) {

			signingCertificateTimestampReferences = new ArrayList<TimestampReference>();
			final NodeList list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CERT_DIGEST);
			for (int jj = 0; jj < list.getLength(); jj++) {

				final Element element = (Element) list.item(jj);
				final TimestampReference signingCertReference = createCertificateTimestampReference(element);
				signingCertificateTimestampReferences.add(signingCertReference);
			}
		}
		return signingCertificateTimestampReferences;
	}

	/**
	 * This method ensures that all Include elements referring to the Reference elements have a referencedData
	 * attribute, which is set to "true". In case one of
	 * these Include elements has its referenceData set to false, the method returns false
	 *
	 * @param timestampToken
	 * @return
	 */
	public boolean checkTimestampTokenIncludes(final TimestampToken timestampToken) {
		final List<TimestampInclude> timestampIncludes = timestampToken.getTimestampIncludes();
		if (Utils.isCollectionNotEmpty(timestampIncludes)) {
			for (final TimestampInclude timestampInclude : timestampIncludes) {
				if (!timestampInclude.isReferencedData()) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public List<TimestampToken> getContentTimestamps() {
		if (contentTimestamps == null) {
			makeTimestampTokens();
		}
		return contentTimestamps;
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() {

		if (signatureTimestamps == null) {
			makeTimestampTokens();
		}
		return signatureTimestamps;
	}

	@Override
	public List<TimestampToken> getTimestampsX1() {

		if (sigAndRefsTimestamps == null) {
			makeTimestampTokens();
		}
		return sigAndRefsTimestamps;
	}

	@Override
	public List<TimestampToken> getTimestampsX2() {

		if (refsOnlyTimestamps == null) {
			makeTimestampTokens();
		}
		return refsOnlyTimestamps;
	}

	@Override
	public List<TimestampToken> getArchiveTimestamps() {

		if (archiveTimestamps == null) {
			makeTimestampTokens();
		}
		return archiveTimestamps;
	}

	/**
	 * This method must not be called more than once.
	 */
	private void makeTimestampTokens() {

		contentTimestamps = new ArrayList<TimestampToken>();
		signatureTimestamps = new ArrayList<TimestampToken>();
		refsOnlyTimestamps = new ArrayList<TimestampToken>();
		sigAndRefsTimestamps = new ArrayList<TimestampToken>();
		archiveTimestamps = new ArrayList<TimestampToken>();
		// TODO (20/12/2014): Browse in the physical order
		final NodeList allDataObjectsTimestamps = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ALL_DATA_OBJECTS_TIMESTAMP);
		addContentTimestamps(contentTimestamps, allDataObjectsTimestamps, TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
		final NodeList individualDataObjectsTimestampsNodes = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
		addContentTimestamps(contentTimestamps, individualDataObjectsTimestampsNodes, TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);

		final Element unsignedSignaturePropertiesDom = getUnsignedSignaturePropertiesDom();
		if (unsignedSignaturePropertiesDom == null) {
			return;
		}
		final List<String> timestampedTimestamps = new ArrayList<String>();
		final NodeList unsignedProperties = unsignedSignaturePropertiesDom.getChildNodes();
		for (int ii = 0; ii < unsignedProperties.getLength(); ii++) {

			final Node node = unsignedProperties.item(ii);
			if (node.getNodeType() != Node.ELEMENT_NODE) {
				// This can happened when there is a blank line between tags.
				continue;
			}
			TimestampToken timestampToken;
			final String localName = node.getLocalName();
			if (XPathQueryHolder.XMLE_SIGNATURE_TIME_STAMP.equals(localName)) {

				timestampToken = makeTimestampToken((Element) node, TimestampType.SIGNATURE_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				timestampToken.setTimestampedReferences(getSignatureTimestampedReferences());
				signatureTimestamps.add(timestampToken);
			} else if (XPathQueryHolder.XMLE_REFS_ONLY_TIME_STAMP.equals(localName) || XPathQueryHolder.XMLE_REFS_ONLY_TIME_STAMP_V2.equals(localName)) {

				timestampToken = makeTimestampToken((Element) node, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				timestampToken.setTimestampedReferences(getTimestampedReferences());
				refsOnlyTimestamps.add(timestampToken);
			} else if (XPathQueryHolder.XMLE_SIG_AND_REFS_TIME_STAMP.equals(localName) || XPathQueryHolder.XMLE_SIG_AND_REFS_TIME_STAMP_V2.equals(localName)) {

				timestampToken = makeTimestampToken((Element) node, TimestampType.VALIDATION_DATA_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				final List<TimestampReference> references = getSignatureTimestampedReferences();
				references.addAll(getTimestampedReferences());
				timestampToken.setTimestampedReferences(references);
				sigAndRefsTimestamps.add(timestampToken);
			} else if (XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP.equals(localName)) {

				timestampToken = makeTimestampToken((Element) node, TimestampType.ARCHIVE_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				final ArchiveTimestampType archiveTimestampType = getArchiveTimestampType(node, localName);
				timestampToken.setArchiveTimestampType(archiveTimestampType);

				final List<TimestampReference> references = getSignatureTimestampedReferences();
				for (final String timestampId : timestampedTimestamps) {
					references.add(new TimestampReference(timestampId, TimestampedObjectType.TIMESTAMP));
				}
				references.addAll(getTimestampedReferences());
				final List<CertificateToken> encapsulatedCertificates = getCertificateSource().getEncapsulatedCertificates();
				for (final CertificateToken certificateToken : encapsulatedCertificates) {
					
					final TimestampReference certificateTimestampReference = createCertificateTimestampReference(certificateToken);
					if (!references.contains(certificateTimestampReference)) {
						references.add(certificateTimestampReference);
					}
				}

				addReferencesFromOfflineCRLSource(references);
				addReferencesFromOfflineOCSPSource(references);

				timestampToken.setTimestampedReferences(references);
				archiveTimestamps.add(timestampToken);
			} else {
				continue;
			}
			timestampedTimestamps.add(timestampToken.getDSSIdAsString());
		}
	}

	private ArchiveTimestampType getArchiveTimestampType(final Node node, final String localName) {
		if (XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP.equals(localName)) {
			final String namespaceURI = node.getNamespaceURI();
			if (XAdESNamespaces.XAdES141.equals(namespaceURI)) {
				return ArchiveTimestampType.XAdES_141;
			}
		}
		return ArchiveTimestampType.XAdES;
	}

	private TimestampReference getSignatureTimestampReference() {
		final TimestampReference signatureReference = new TimestampReference(getId());
		return signatureReference;
	}

	private String getTimestampCanonicalizationMethod(final Element timestampElement) {
		final Element canonicalizationMethodElement = DomUtils.getElement(timestampElement, xPathQueryHolder.XPATH__CANONICALIZATION_METHOD);
		if (canonicalizationMethodElement != null) {
			return canonicalizationMethodElement.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
		}
		return null;
	}

	/*
	 * Returns the list of certificates encapsulated in the KeyInfo segment
	 */
	public List<CertificateToken> getKeyInfoCertificates() {

		return getCertificateSource().getKeyInfoCertificates();
	}

	/*
	 * Returns the list of certificates encapsulated in the KeyInfo segment
	 */
	public List<CertificateToken> getTimestampCertificates() {

		return getCertificateSource().getTimestampCertificates();
	}

	@Override
	public void checkSignatureIntegrity() {
		if (signatureCryptographicVerification != null) {
			return;
		}
		signatureCryptographicVerification = new SignatureCryptographicVerification();
		try {
			final XMLSignature santuarioSignature = getSantuarioSignature();

			boolean coreValidity = false;
			final List<CertificateValidity> certificateValidityList = getSigningCertificateValidityList(santuarioSignature, signatureCryptographicVerification,
					providedSigningCertificateToken);
			LOG.debug("Determining signing certificate from certificate candidates list");
			final List<String> preliminaryErrorMessages = new ArrayList<String>();
			int certificateNumber = 0;
			for (final CertificateValidity certificateValidity : certificateValidityList) {
				String errorMessagePrefix = "Certificate #" + (certificateNumber + 1) + ": ";
				try {

					final PublicKey publicKey = certificateValidity.getPublicKey();
					coreValidity = santuarioSignature.checkSignatureValue(publicKey);
					if (coreValidity) {
						LOG.info("Determining signing certificate from certificate candidates list succeeded");
						candidatesForSigningCertificate.setTheCertificateValidity(certificateValidity);
						break;
					} else {
						// upon returning false, santuarioSignature (class XMLSignature) will log "Signature
						// verification failed." with WARN level.
						preliminaryErrorMessages.add(errorMessagePrefix + "Signature verification failed");
					}
				} catch (XMLSignatureException e) {
					LOG.debug("Exception while probing candidate certificate as signing certificate: {}",
							e.getMessage());
					preliminaryErrorMessages.add(errorMessagePrefix + e.getMessage());
				}
				certificateNumber++;
			}
			if (!coreValidity) {
				LOG.warn("Determining signing certificate from certificate candidates list failed: {}", preliminaryErrorMessages);
				for (String preliminaryErrorMessage : preliminaryErrorMessages) {
					signatureCryptographicVerification.setErrorMessage(preliminaryErrorMessage);
				}
			}

			boolean allReferenceDataFound = true;
			boolean allReferenceDataIntact = true;
			List<ReferenceValidation> refValidations = getReferenceValidations();
			for (ReferenceValidation referenceValidation : refValidations) {
				allReferenceDataFound = allReferenceDataFound && referenceValidation.isFound();
				allReferenceDataIntact = allReferenceDataIntact && referenceValidation.isIntact();
			}

			signatureCryptographicVerification.setReferenceDataFound(allReferenceDataFound);
			signatureCryptographicVerification.setReferenceDataIntact(allReferenceDataIntact);
			signatureCryptographicVerification.setSignatureIntact(coreValidity);
		} catch (Exception e) {
			LOG.error("checkSignatureIntegrity : {}", e.getMessage());
			LOG.debug("checkSignatureIntegrity : " + e.getMessage(), e);
			StackTraceElement[] stackTrace = e.getStackTrace();
			final String name = XAdESSignature.class.getName();
			int lineNumber = 0;
			for (StackTraceElement element : stackTrace) {

				final String className = element.getClassName();
				if (className.equals(name)) {

					lineNumber = element.getLineNumber();
					break;
				}
			}
			signatureCryptographicVerification.setErrorMessage(e.getMessage() + "/ XAdESSignature/Line number/" + lineNumber);
		}
	}

	@Override
	public List<ReferenceValidation> getReferenceValidations() {
		if (referenceValidations == null) {
			referenceValidations = new ArrayList<ReferenceValidation>();

			final XMLSignature santuarioSignature = getSantuarioSignature();
			final SignedInfo signedInfo = santuarioSignature.getSignedInfo();
			final int numberOfReferences = signedInfo.getLength();

			boolean signedPropertiesFound = false;
			boolean referenceFound = false;
			for (int ii = 0; ii < numberOfReferences; ii++) {
				ReferenceValidation validation = new ReferenceValidation();
				boolean found = false;
				boolean intact = false;
				try {
					final Reference reference = signedInfo.item(ii);
					references.add(reference);

					final String id = reference.getId();
					final String uri = reference.getURI();
					if (Utils.isStringNotBlank(id)) {
						validation.setName(id);
					} else if (Utils.isStringNotBlank(uri)) {
						validation.setName(uri);
					}

					found = reference.getContentsBeforeTransformation() != null;
					boolean noDuplicateIdFound = XMLUtils.protectAgainstWrappingAttack(santuarioSignature.getDocument(), DomUtils.getId(uri));
					if (isSignedProperties(reference)) {
						validation.setType(DigestMatcherType.SIGNED_PROPERTIES);
						found = found && (noDuplicateIdFound && findSignedPropertiesById(uri));
						signedPropertiesFound = signedPropertiesFound || found;
					} else if (isKeyInfoReference(reference, santuarioSignature.getElement())) {
						validation.setType(DigestMatcherType.KEY_INFO);
						found = true; // we check it in prior inside "isKeyInfoReference" method
					} else if (reference.typeIsReferenceToObject()) {
						validation.setType(DigestMatcherType.OBJECT);
						found = found &&  (noDuplicateIdFound && findObjectById(uri));
						referenceFound = referenceFound || found;
					} else if (reference.typeIsReferenceToManifest()) {
						validation.setType(DigestMatcherType.MANIFEST);
						Node manifestNode = getManifestById(uri);
						found = found && (noDuplicateIdFound && (manifestNode != null));
						referenceFound = referenceFound || found;
						if (manifestNode != null && Utils.isCollectionNotEmpty(detachedContents)) {
							ManifestValidator mv = new ManifestValidator(manifestNode, detachedContents, xPathQueryHolder);
							referenceValidations.addAll(mv.validate());
						}
					} else {
						validation.setType(DigestMatcherType.REFERENCE);
						found = found && noDuplicateIdFound;
						referenceFound = referenceFound || found;
					}

					final Digest digest = new Digest();
					digest.setValue(reference.getDigestValue());
					digest.setAlgorithm(
							DigestAlgorithm.forXML(reference.getMessageDigestAlgorithm().getAlgorithmURI()));
					validation.setDigest(digest);

					intact = reference.verify();
				} catch (XMLSecurityException e) {
					LOG.warn("Unable to verify reference {} : {}", ii, e.getMessage());
				}
				validation.setFound(found);
				validation.setIntact(intact);
				referenceValidations.add(validation);
			}

			// If at least one signedProperties is not found, we add an empty
			// referenceValidation
			if (!signedPropertiesFound) {
				referenceValidations.add(notFound(DigestMatcherType.SIGNED_PROPERTIES));
			}
			// If at least one reference is not found, we add an empty
			// referenceValidation
			if (!referenceFound) {
				referenceValidations.add(notFound(DigestMatcherType.REFERENCE));
			}
		}
		return referenceValidations;
	}

	private boolean isSignedProperties(final Reference reference) {
		return xPathQueryHolder.XADES_SIGNED_PROPERTIES.equals(reference.getType());
	}

	private boolean findSignedPropertiesById(String uri) {
		return getSignedPropertiesById(uri) != null;
	}

	private Node getSignedPropertiesById(String uri) {
		String signedPropertiesById = xPathQueryHolder.XPATH_SIGNED_PROPERTIES + DomUtils.getXPathByIdAttribute(uri);
		return DomUtils.getNode(signatureElement, signedPropertiesById);
	}
	
	/**
	 * Checks if the given {@value reference} is linked to a <KeyInfo> element
	 * @param reference - {@link Reference} to check
	 * @param signature - {@link Element} signature the given {@value reference} belongs to
	 * @return - TRUE if the {@value reference} is a <KeyInfo> reference, FALSE otherwise
	 */
	private boolean isKeyInfoReference(final Reference reference, final Element signature) {
		String uri = reference.getURI();
		uri = DomUtils.getId(uri);
		Element element = DomUtils.getElement(signature, "./" + xPathQueryHolder.XPATH_KEY_INFO + DomUtils.getXPathByIdAttribute(uri));
		if (element != null) {
			return true;
		}
		return false;
	}

	private boolean findObjectById(String uri) {
		return getObjectById(uri) != null;
	}

	public Node getObjectById(String uri) {
		String objectById = XPathQueryHolder.XPATH_OBJECT + DomUtils.getXPathByIdAttribute(uri);
		return DomUtils.getNode(signatureElement, objectById);
	}

	public Node getManifestById(String uri) {
		String manifestById = XPathQueryHolder.XPATH_MANIFEST + DomUtils.getXPathByIdAttribute(uri);
		return DomUtils.getNode(signatureElement, manifestById);
	}

	private ReferenceValidation notFound(DigestMatcherType type) {
		ReferenceValidation validation = new ReferenceValidation();
		validation.setType(type);
		validation.setFound(false);
		return validation;
	}

	private XMLSignature getSantuarioSignature() {
		try {
			final Document document = signatureElement.getOwnerDocument();
			final Element rootElement = document.getDocumentElement();

			DSSXMLUtils.setIDIdentifier(rootElement);
			DSSXMLUtils.recursiveIdBrowse(rootElement);

			final XMLSignature santuarioSignature = new XMLSignature(signatureElement, "");
			if (Utils.isCollectionNotEmpty(detachedContents)) {
				santuarioSignature.addResourceResolver(new DetachedSignatureResolver(detachedContents, getSignatureAlgorithm().getDigestAlgorithm()));
			}
			return santuarioSignature;
		} catch (XMLSecurityException e) {
			throw new DSSException("Unable to initialize santuario XMLSignature", e);
		}
	}

	/**
	 * This method returns a {@code List} of {@code SigningCertificateValidity} base on the certificates extracted from
	 * the signature or on the
	 * {@code providedSigningCertificateToken}. The field {@code candidatesForSigningCertificate} is instantiated in
	 * case where the signing certificated is
	 * provided.
	 *
	 * @param santuarioSignature
	 *            The object created tro validate the signature
	 * @param scv
	 *            {@code SignatureCryptographicVerification} containing information on the signature validation
	 * @param providedSigningCertificate
	 *            provided signing certificate: {@code CertificateToken} @return
	 * @return the {@code List} of the {@code SigningCertificateValidity}
	 * @throws KeyResolverException
	 */
	private List<CertificateValidity> getSigningCertificateValidityList(final XMLSignature santuarioSignature, SignatureCryptographicVerification scv,
			final CertificateToken providedSigningCertificate) throws KeyResolverException {

		List<CertificateValidity> certificateValidityList;
		if (providedSigningCertificate == null) {

			// To determine the signing certificate it is necessary to browse
			// through all candidates extracted from the signature.
			final CandidatesForSigningCertificate candidates = getCandidatesForSigningCertificate();
			certificateValidityList = candidates.getCertificateValidityList();
			if (certificateValidityList.isEmpty()) {

				// The public key can also be extracted from the signature.
				final KeyInfo extractedKeyInfo = santuarioSignature.getKeyInfo();
				final PublicKey publicKey;
				if ((extractedKeyInfo == null) || ((publicKey = extractedKeyInfo.getPublicKey()) == null)) {

					scv.setErrorMessage("There is no signing certificate within the signature.");
					return certificateValidityList;
				}
				certificateValidityList = getSigningCertificateValidityList(publicKey);
			}
		} else {

			candidatesForSigningCertificate = new CandidatesForSigningCertificate();
			final CertificateValidity certificateValidity = new CertificateValidity(providedSigningCertificate);
			candidatesForSigningCertificate.add(certificateValidity);
			certificateValidityList = candidatesForSigningCertificate.getCertificateValidityList();
		}
		return certificateValidityList;
	}

	/**
	 * This method returns a {@code List} of {@code SigningCertificateValidity} base on the provided
	 * {@code providedSigningCertificateToken}. The field
	 * {@code candidatesForSigningCertificate} is instantiated.
	 *
	 * @param extractedPublicKey
	 *            provided public key: {@code PublicKey}
	 * @return
	 */
	protected List<CertificateValidity> getSigningCertificateValidityList(final PublicKey extractedPublicKey) {

		candidatesForSigningCertificate = new CandidatesForSigningCertificate();
		final CertificateValidity certificateValidity = new CertificateValidity(extractedPublicKey);
		candidatesForSigningCertificate.add(certificateValidity);
		final List<CertificateValidity> certificateValidityList = candidatesForSigningCertificate.getCertificateValidityList();
		return certificateValidityList;
	}

	/**
	 * This method retrieves the potential countersignatures embedded in the XAdES signature document. From ETSI TS 101
	 * 903 v1.4.2:
	 *
	 * 7.2.4.1 Countersignature identifier in Type attribute of ds:Reference
	 *
	 * A XAdES signature containing a ds:Reference element whose Type attribute has value
	 * "http://uri.etsi.org/01903#CountersignedSignature" will indicate that
	 * is is, in fact, a countersignature of the signature referenced by this element.
	 *
	 * 7.2.4.2 Enveloped countersignatures: the CounterSignature element
	 *
	 * The CounterSignature is an unsigned property that qualifies the signature. A XAdES signature MAY have more than
	 * one CounterSignature properties. As
	 * indicated by its name, it contains one countersignature of the qualified signature.
	 *
	 * @return a list containing the countersignatures embedded in the XAdES signature document
	 */
	@Override
	public List<AdvancedSignature> getCounterSignatures() {

		// see ETSI TS 101 903 V1.4.2 (2010-12) pp. 38/39/40
		final NodeList counterSignatures = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_COUNTER_SIGNATURE);
		if (counterSignatures == null) {
			return null;
		}
		final List<AdvancedSignature> xadesList = new ArrayList<AdvancedSignature>();
		for (int ii = 0; ii < counterSignatures.getLength(); ii++) {

			final Element counterSignatureElement = (Element) counterSignatures.item(ii);
			final Element signatureElement = DomUtils.getElement(counterSignatureElement, xPathQueryHolder.XPATH__SIGNATURE);

			// Verify that the element is a proper signature by trying to build
			// a XAdESSignature out of it
			final XAdESSignature xadesCounterSignature = new XAdESSignature(signatureElement, xPathQueryHolders, certPool);
			if (isCounterSignature(xadesCounterSignature)) {
				xadesCounterSignature.setMasterSignature(this);
				xadesList.add(xadesCounterSignature);
			}
		}
		return xadesList;
	}

	/**
	 * This method verifies whether a given signature is a countersignature.
	 *
	 * From ETSI TS 101 903 V1.4.2: - The signature's ds:SignedInfo element MUST contain one ds:Reference element
	 * referencing the ds:Signature element of the
	 * embedding and countersigned XAdES signature - The content of the ds:DigestValue in the aforementioned
	 * ds:Reference element of the countersignature MUST
	 * be the base-64 encoded digest of the complete (and canonicalized) ds:SignatureValue element (i.e. including the
	 * starting and closing tags) of the
	 * embedding and countersigned XAdES signature.
	 *
	 * @param xadesCounterSignature
	 * @return
	 */
	private boolean isCounterSignature(final XAdESSignature xadesCounterSignature) {

		final List<Element> signatureReferences = xadesCounterSignature.getSignatureReferences();
		// gets Element with
		// Type="http://uri.etsi.org/01903#CountersignedSignature"
		for (final Element reference : signatureReferences) {

			final String type = reference.getAttribute("Type");
			if (xPathQueryHolder.XADES_COUNTERSIGNED_SIGNATURE.equals(type)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public List<CertificateRef> getCertificateRefs() {

		Element signingCertEl = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_CERT_REFS);
		if (signingCertEl == null) {

			return null;
		}
		List<CertificateRef> certIds = new ArrayList<CertificateRef>();
		NodeList certIdnodes = DomUtils.getNodeList(signingCertEl, "./xades:Cert");
		for (int i = 0; i < certIdnodes.getLength(); i++) {

			Element certId = (Element) certIdnodes.item(i);
			Element issuerNameEl = DomUtils.getElement(certId, xPathQueryHolder.XPATH__X509_ISSUER_NAME);
			Element issuerSerialEl = DomUtils.getElement(certId, xPathQueryHolder.XPATH__X509_SERIAL_NUMBER);
			Element digestAlgorithmEl = DomUtils.getElement(certId, xPathQueryHolder.XPATH__CERT_DIGEST_DIGEST_METHOD);
			Element digestValueEl = DomUtils.getElement(certId, xPathQueryHolder.XPATH__CERT_DIGEST_DIGEST_VALUE);

			CertificateRef genericCertId = new CertificateRef();
			if ((issuerNameEl != null) && (issuerSerialEl != null)) {
				genericCertId.setIssuerName(issuerNameEl.getTextContent());
				genericCertId.setIssuerSerial(issuerSerialEl.getTextContent());
			}

			String xmlName = digestAlgorithmEl.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
			genericCertId.setDigestAlgorithm(DigestAlgorithm.forXML(xmlName));

			genericCertId.setDigestValue(Utils.fromBase64(digestValueEl.getTextContent()));
			certIds.add(genericCertId);
		}

		return certIds;

	}

	@Override
	public List<CRLRef> getCRLRefs() {
		final List<CRLRef> crlRefs = new ArrayList<CRLRef>();
		final Element crlRefsElement = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_REVOCATION_CRL_REFS);
		if (crlRefsElement != null) {

			final NodeList crlRefNodes = DomUtils.getNodeList(crlRefsElement, xPathQueryHolder.XPATH__CRL_REF);
			for (int i = 0; i < crlRefNodes.getLength(); i++) {

				final Element crlRefNode = (Element) crlRefNodes.item(i);
				final Element digestAlgorithmEl = DomUtils.getElement(crlRefNode, xPathQueryHolder.XPATH__DAAV_DIGEST_METHOD);
				final Element digestValueEl = DomUtils.getElement(crlRefNode, xPathQueryHolder.XPATH__DAAV_DIGEST_VALUE);

				final String xmlName = digestAlgorithmEl.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
				final DigestAlgorithm digestAlgo = DigestAlgorithm.forXML(xmlName);

				crlRefs.add(new CRLRef(digestAlgo, Utils.fromBase64(digestValueEl.getTextContent())));
			}
		}
		return crlRefs;
	}

	@Override
	public List<OCSPRef> getOCSPRefs() {
		final List<OCSPRef> ocspRefs = new ArrayList<OCSPRef>();
		final Element ocspRefsElement = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_OCSP_REFS);
		if (ocspRefsElement != null) {

			final NodeList ocspRefNodes = DomUtils.getNodeList(ocspRefsElement, xPathQueryHolder.XPATH__OCSPREF);
			for (int i = 0; i < ocspRefNodes.getLength(); i++) {

				final Element certId = (Element) ocspRefNodes.item(i);
				final Element digestAlgorithmEl = DomUtils.getElement(certId, xPathQueryHolder.XPATH__DAAV_DIGEST_METHOD);
				final Element digestValueEl = DomUtils.getElement(certId, xPathQueryHolder.XPATH__DAAV_DIGEST_VALUE);

				final String xmlName = digestAlgorithmEl.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
				final DigestAlgorithm digestAlgo = DigestAlgorithm.forXML(xmlName);

				final String digestValue = digestValueEl.getTextContent();
				final byte[] base64EncodedDigestValue = Utils.fromBase64(digestValue);
				ocspRefs.add(new OCSPRef(digestAlgo, base64EncodedDigestValue, false));
			}
		}
		return ocspRefs;
	}

	@Override
	public byte[] getSignatureTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) {
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;

		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			writeCanonicalizedValue(xPathQueryHolder.XPATH_SIGNATURE_VALUE, canonicalizationMethod, buffer);
			final byte[] byteArray = buffer.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("Signature timestamp canonicalized string : \n{}", new String(byteArray));
			}
			return byteArray;
		} catch (IOException e) {
			throw new DSSException("Error when computing the SignatureTimestamp", e);
		}
	}

	@Override
	public byte[] getTimestampX1Data(final TimestampToken timestampToken, String canonicalizationMethod) {
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;

		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			writeCanonicalizedValue(xPathQueryHolder.XPATH_SIGNATURE_VALUE, canonicalizationMethod, buffer);

			final NodeList signatureTimeStampNode = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_TIMESTAMP);
			if (signatureTimeStampNode != null) {
				for (int ii = 0; ii < signatureTimeStampNode.getLength(); ii++) {

					final Node item = signatureTimeStampNode.item(ii);
					final byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, item);
					buffer.write(canonicalizedValue);
				}
			}
			writeCanonicalizedValue(xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS, canonicalizationMethod, buffer);
			writeCanonicalizedValue(xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS, canonicalizationMethod, buffer);
			final byte[] byteArray = buffer.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("X1Timestamp (SigAndRefsTimeStamp) canonicalised string : \n{}", new String(byteArray));
			}
			return byteArray;
		} catch (IOException e) {
			throw new DSSException("Error when computing the SigAndRefsTimeStamp (X1Timestamp)", e);
		}
	}

	@Override
	public byte[] getTimestampX2Data(final TimestampToken timestampToken, String canonicalizationMethod) {
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;

		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			writeCanonicalizedValue(xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS, canonicalizationMethod, buffer);
			writeCanonicalizedValue(xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS, canonicalizationMethod, buffer);

			final byte[] byteArray = buffer.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("TimestampX2Data (RefsOnlyTimeStamp) canonicalised string : \n{}", new String(byteArray));
			}
			return byteArray;
		} catch (IOException e) {
			throw new DSSException("Error when computing the RefsOnlyTimeStamp (TimestampX2D)", e);
		}
	}

	/**
	 * Gathers the data to be used to calculate the hash value sent to the TSA (messageImprint).
	 *
	 * @param timestampToken
	 *            {@code TimestampToken} to validate, or {@code null} when adding a new archive timestamp
	 * @param canonicalizationMethod
	 * @return {@code byte} array containing the canonicalized and concatenated timestamped data
	 */
	@Override
	public byte[] getArchiveTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) {

		if (LOG.isTraceEnabled()) {
			LOG.trace("--->Get archive timestamp data:" + (timestampToken == null ? "--> CREATION" : "--> VALIDATION"));
		}
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		/**
		 * 8.2.1 Not distributed case<br>
		 *
		 * When xadesv141:ArchiveTimeStamp and all the unsigned properties covered by its time-stamp certificateToken
		 * have the same parent, this property uses
		 * the Implicit mechanism for all the time-stamped data objects. The input to the computation of the digest
		 * value MUST be built as follows:
		 * 
		 * 1) Initialize the final octet stream as an empty octet stream.
		 */
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {

			/**
			 * 2) Take all the ds:Reference elements in their order of appearance within ds:SignedInfo referencing
			 * whatever the signer wants to sign including
			 * the SignedProperties element. Process each one as indicated below:<br>
			 * - Process the retrieved ds:Reference element according to the reference processing model of XMLDSIG.<br>
			 * - If the result is a XML node set, canonicalize it. If ds:Canonicalization is present, the algorithm
			 * indicated by this element is used. If not,
			 * the standard canonicalization method specified by XMLDSIG is used.<br>
			 * - Concatenate the resulting octets to the final octet stream.
			 */

			/**
			 * The references are already calculated {@see #checkSignatureIntegrity()}
			 */
			final Set<String> referenceURIs = new HashSet<String>();
			for (final Reference reference : references) {
				referenceURIs.add(cleanURI(reference.getURI()));
				try {
					final byte[] referencedBytes = reference.getReferencedBytes();
					if (referencedBytes != null) {
						buffer.write(referencedBytes);
					} else {
						LOG.warn("No binaries found for URI '{}'", reference.getURI());
					}
				} catch (XMLSecurityException e) {
					LOG.warn("Unable to retrieve content for URI '{}' : {}", reference.getURI(), e.getMessage());
				}
			}

			/**
			 * 3) Take the following XMLDSIG elements in the order they are listed below, canonicalize each one and
			 * concatenate each resulting octet stream to
			 * the final octet stream:<br>
			 * - The ds:SignedInfo element.<br>
			 * - The ds:SignatureValue element.<br>
			 * - The ds:KeyInfo element, if present.
			 */
			writeCanonicalizedValue(xPathQueryHolder.XPATH_SIGNED_INFO, canonicalizationMethod, buffer);
			writeCanonicalizedValue(xPathQueryHolder.XPATH_SIGNATURE_VALUE, canonicalizationMethod, buffer);
			writeCanonicalizedValue(xPathQueryHolder.XPATH_KEY_INFO, canonicalizationMethod, buffer);
			/**
			 * 4) Take the unsigned signature properties that appear before the current xadesv141:ArchiveTimeStamp in
			 * the order they appear within the
			 * xades:UnsignedSignatureProperties, canonicalize each one and concatenate each resulting octet stream to
			 * the final octet stream. While
			 * concatenating the following rules apply:
			 */
			final Element unsignedSignaturePropertiesDom = getUnsignedSignaturePropertiesDom();
			if (unsignedSignaturePropertiesDom == null) {
				throw new NullPointerException(xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
			}
			final NodeList unsignedProperties = unsignedSignaturePropertiesDom.getChildNodes();
			for (int ii = 0; ii < unsignedProperties.getLength(); ii++) {

				final Node node = unsignedProperties.item(ii);
				if (node.getNodeType() != Node.ELEMENT_NODE) {
					// This can happened when there is a blank line between tags.
					continue;
				}
				final String localName = node.getLocalName();
				// In the SD-DSS implementation when validating the signature
				// the framework will not add missing data. To do so the
				// signature must be extended.
				// if (localName.equals("CertificateValues")) {
				/*
				 * - The xades:CertificateValues property MUST be added if it is not already present and the ds:KeyInfo
				 * element does not contain the full set of
				 * certificates used to validate the electronic signature.
				 */
				// } else if (localName.equals("RevocationValues")) {
				/*
				 * - The xades:RevocationValues property MUST be added if it is not already present and the ds:KeyInfo
				 * element does not contain the revocation
				 * information that has to be shipped with the electronic signature
				 */
				// } else if (localName.equals("AttrAuthoritiesCertValues")) {
				/*
				 * - The xades:AttrAuthoritiesCertValues property MUST be added if not already present and the following
				 * conditions are true: there exist an
				 * attribute certificate in the signature AND a number of certificates that have been used in its
				 * validation do not appear in CertificateValues.
				 * Its content will satisfy with the rules specified in clause 7.6.3.
				 */
				// } else if (localName.equals("AttributeRevocationValues")) {
				/*
				 * - The xades:AttributeRevocationValues property MUST be added if not already present and there the
				 * following conditions are true: there exist
				 * an attribute certificate AND some revocation data that have been used in its validation do not appear
				 * in RevocationValues. Its content will
				 * satisfy with the rules specified in clause 7.6.4.
				 */
				// } else
				if (XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP.equals(localName)) {

					if ((timestampToken != null) && (timestampToken.getHashCode() == node.hashCode())) {
						break;
					}
				} else if ("TimeStampValidationData".equals(localName)) {

					/**
					 * ETSI TS 101 903 V1.4.2 (2010-12) 8.1 The new XAdESv141:TimeStampValidationData element ../.. This
					 * element is specified to serve as an
					 * optional container for validation data required for carrying a full verification of time-stamp
					 * tokens embedded within any of the
					 * different time-stamp containers defined in the present document. ../.. 8.1.1 Use of URI attribute
					 * ../.. a new
					 * xadesv141:TimeStampValidationData element SHALL be created containing the missing validation data
					 * information and it SHALL be added as a
					 * child of UnsignedSignatureProperties elements immediately after the respective time-stamp
					 * certificateToken container element.
					 */
				}
				byte[] canonicalizedValue;
				if (timestampToken == null) { // Creation of the timestamp

					/**
					 * This is the work around for the name space problem: The issue was reported on:
					 * https://issues.apache.org/jira/browse/SANTUARIO-139 and
					 * considered as close. But for me (Bob) it still does not work!
					 */
					final byte[] bytesToCanonicalize = DSSXMLUtils.serializeNode(node);
					canonicalizedValue = DSSXMLUtils.canonicalize(canonicalizationMethod, bytesToCanonicalize);
				} else {
					canonicalizedValue = DSSXMLUtils.canonicalizeOrSerializeSubtree(canonicalizationMethod, node);
				}
				if (LOG.isTraceEnabled()) {
					LOG.trace("{}: Canonicalization: {} : \n", localName, canonicalizationMethod,
							new String(canonicalizedValue));
				}
				buffer.write(canonicalizedValue);
			}
			/**
			 * 5) Take all the ds:Object elements except the one containing xades:QualifyingProperties element.
			 * Canonicalize each one and concatenate each
			 * resulting octet stream to the final octet stream. If ds:Canonicalization is present, the algorithm
			 * indicated by this element is used. If not, the
			 * standard canonicalization method specified by XMLDSIG is used.
			 */
			boolean xades141 = (timestampToken == null) || !ArchiveTimestampType.XAdES.equals(timestampToken.getArchiveTimestampType());

			final NodeList objects = getObjects();
			for (int ii = 0; ii < objects.getLength(); ii++) {

				final Node node = objects.item(ii);
				final Node qualifyingProperties = DomUtils.getElement(node, xPathQueryHolder.XPATH__QUALIFYING_PROPERTIES);
				if (qualifyingProperties != null) {
					continue;
				}
				if (!xades141) {
					/**
					 * !!! ETSI TS 101 903 V1.3.2 (2006-03) 5) Take any ds:Object element in the signature that is not
					 * referenced by any ds:Reference within
					 * ds:SignedInfo, except that one containing the QualifyingProperties element. Canonicalize each one
					 * and concatenate each resulting octet
					 * stream to the final octet stream. If ds:Canonicalization is present, the algorithm indicated by
					 * this element is used. If not, the
					 * standard canonicalization method specified by XMLDSIG is used.
					 */
					final NamedNodeMap attributes = node.getAttributes();
					final int length = attributes.getLength();
					String id = "";
					for (int jj = 0; jj < length; jj++) {
						final Node item = attributes.item(jj);
						final String nodeName = item.getNodeName();
						if (Utils.areStringsEqualIgnoreCase("ID", nodeName)) {
							id = item.getNodeValue();
							break;
						}
					}
					final boolean contains = referenceURIs.contains(id);
					if (contains) {
						continue;
					}
				}
				byte[] canonicalizedValue = DSSXMLUtils.canonicalizeOrSerializeSubtree(canonicalizationMethod, node);
				buffer.write(canonicalizedValue);
			}
			
			byte[] bytes = buffer.toByteArray();
			if(LOG.isTraceEnabled()) {
				LOG.trace("Data to TimeStamp:");
				LOG.trace(new String(bytes));
			}
			return bytes;
		} catch (IOException e) {
			throw new DSSException("Error when computing the archive data", e);
		}
	}

	/**
	 * This methods removes the char '#' if present
	 * 
	 * @param uri
	 * @return cleaned uri
	 */
	private String cleanURI(final String uri) {
		if (uri.startsWith("#")) {
			return uri.substring(1);
		}
		return uri;
	}

	private void writeCanonicalizedValue(final String xPathString, final String canonicalizationMethod, final ByteArrayOutputStream buffer) throws IOException {
		final Element element = DomUtils.getElement(signatureElement, xPathString);
		if (element != null) {
			buffer.write(DSSXMLUtils.canonicalizeOrSerializeSubtree(canonicalizationMethod, element));
		}
	}

	@Override
	public String getId() {

		if (signatureId == null) {

			String idValue = DSSXMLUtils.getIDIdentifier(signatureElement);
			if (idValue != null) {

				signatureId = idValue;
			} else {

				final CertificateToken certificateToken = getSigningCertificateToken();
				TokenIdentifier identifier = certificateToken == null ? null : certificateToken.getDSSId();
				signatureId = DSSUtils.getDeterministicId(getSigningTime(), identifier);
			}
		}
		return signatureId;
	}

	@Override
	public List<TimestampReference> getTimestampedReferences() {

		final List<TimestampReference> references = new ArrayList<TimestampReference>();

		final Node completeCertificateRefsNode = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS);
		if (completeCertificateRefsNode != null) {

			final NodeList nodes = DomUtils.getNodeList(completeCertificateRefsNode, xPathQueryHolder.XPATH__COMPLETE_CERTIFICATE_REFS__CERT_DIGEST);
			for (int ii = 0; ii < nodes.getLength(); ii++) {

				final Element certDigestElement = (Element) nodes.item(ii);
				final TimestampReference certificateReference = createCertificateTimestampReference(certDigestElement);
				references.add(certificateReference);
			}
		}
		final Node completeRevocationRefsNode = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS);
		if (completeRevocationRefsNode != null) {

			final NodeList nodes = DomUtils.getNodeList(completeRevocationRefsNode, "./*/*/xades:DigestAlgAndValue");
			for (int ii = 0; ii < nodes.getLength(); ii++) {

				final Element element = (Element) nodes.item(ii);
				final TimestampReference revocationReference = createRevocationTimestampReference(element);
				references.add(revocationReference);
			}
		}
		return references;
	}

	private TimestampReference createRevocationTimestampReference(Element element) {
		String digestAlgorithmStr = DomUtils.getNode(element, xPathQueryHolder.XPATH__DIGEST_METHOD_ALGORITHM).getTextContent();
		DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(digestAlgorithmStr);
		final String digestValue = DomUtils.getElement(element, xPathQueryHolder.XPATH__DIGEST_VALUE).getTextContent();
		final TimestampReference revocationReference = new TimestampReference(digestAlgorithm, digestValue);
		return revocationReference;
	}

	/**
	 * Retrieves the name of each node found under the unsignedSignatureProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getUnsignedSignatureProperties() {

		final List<String> childrenNames = DomUtils.getChildrenNames(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
		return childrenNames;
	}

	public List<String> getSignedSignatureProperties() {

		final List<String> childrenNames = DomUtils.getChildrenNames(signatureElement, xPathQueryHolder.XPATH_SIGNED_SIGNATURE_PROPERTIES);
		return childrenNames;
	}

	public List<String> getSignedProperties() {

		final List<String> childrenNames = DomUtils.getChildrenNames(signatureElement, xPathQueryHolder.XPATH_SIGNED_PROPERTIES);
		return childrenNames;
	}

	public List<String> getUnsignedProperties() {

		final List<String> childrenNames = DomUtils.getChildrenNames(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_PROPERTIES);
		return childrenNames;
	}

	public List<String> getSignedDataObjectProperties() {

		final List<String> childrenNames = DomUtils.getChildrenNames(signatureElement, xPathQueryHolder.XPATH_SIGNED_DATA_OBJECT_PROPERTIES);
		return childrenNames;
	}

	/**
	 * This method creates
	 *
	 * @param element
	 * @return
	 * @throws eu.europa.esig.dss.DSSException
	 */
	private TimestampReference createCertificateTimestampReference(final Element element) throws DSSException {

		final String xmlDigestAlgorithm = DomUtils.getNode(element, xPathQueryHolder.XPATH__DIGEST_METHOD_ALGORITHM).getTextContent();
		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(xmlDigestAlgorithm);
		usedCertificatesDigestAlgorithms.add(digestAlgorithm);
		final Element digestValueElement = DomUtils.getElement(element, xPathQueryHolder.XPATH__DIGEST_VALUE);
		final String digestValue = (digestValueElement == null) ? "" : digestValueElement.getTextContent();
		final TimestampReference reference = new TimestampReference(digestAlgorithm, digestValue);
		return reference;
	}

	private TimestampReference createCertificateTimestampReference(final CertificateToken certificateToken) throws DSSException {

		usedCertificatesDigestAlgorithms.add(DigestAlgorithm.SHA1);

		final TimestampReference reference = new TimestampReference(DigestAlgorithm.SHA1, Utils.toBase64(certificateToken.getDigest(DigestAlgorithm.SHA1)));
		return reference;
	}

	@Override
	public boolean isDataForSignatureLevelPresent(final SignatureLevel signatureLevel) {

		boolean dataForLevelPresent = true;
		switch (signatureLevel) {
		case XML_NOT_ETSI:
			break;
		case XAdES_BASELINE_LTA:
			dataForLevelPresent = hasLTAProfile();
			dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.XAdES_BASELINE_LT);
			break;
		case XAdES_BASELINE_LT:
			dataForLevelPresent = hasLTProfile();
			dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.XAdES_BASELINE_T);
			break;
		case XAdES_BASELINE_T:
			dataForLevelPresent = hasTProfile();
			dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.XAdES_BASELINE_B);
			break;
		case XAdES_BASELINE_B:
			dataForLevelPresent = hasBProfile();
			break;
		case XAdES_X:
			dataForLevelPresent = hasXProfile();
			dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.XAdES_C);
			break;
		case XAdES_C:
			dataForLevelPresent = hasCProfile();
			dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.XAdES_BASELINE_T);
			break;
		default:
			throw new IllegalArgumentException("Unknown level " + signatureLevel);
		}
		return dataForLevelPresent;
	}

	@Override
	public SignatureLevel[] getSignatureLevels() {

		return signatureLevels;
	}

	@Override
	public void validateStructure() {
		final String string = DomUtils.xmlToString(signatureElement);
		StringReader stringReader = new StringReader(string);
		structureValidation = DSSXMLUtils.validateAgainstXSD(new StreamSource(stringReader));
	}

	/**
	 * This method returns the last timestamp validation data for an archive timestamp.
	 *
	 * @return
	 */
	public Element getLastTimestampValidationData() {
		final List<TimestampToken> archiveTimestamps = getArchiveTimestamps();
		TimestampToken mostRecentTimestamp = null;
		for (final TimestampToken archiveTimestamp : archiveTimestamps) {
			if (mostRecentTimestamp == null) {
				mostRecentTimestamp = archiveTimestamp;
				continue;
			}
			final Date generationTime = archiveTimestamp.getGenerationTime();
			final Date mostRecentGenerationTime = mostRecentTimestamp.getGenerationTime();
			if (generationTime.after(mostRecentGenerationTime)) {
				mostRecentTimestamp = archiveTimestamp;
			}
		}

		if (mostRecentTimestamp != null) {
			final int timestampHashCode = mostRecentTimestamp.getHashCode();
			final NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/*");
			boolean found = false;
			for (int ii = 0; ii < nodeList.getLength(); ii++) {
				final Element unsignedSignatureElement = (Element) nodeList.item(ii);
				final int nodeHashCode = unsignedSignatureElement.hashCode();
				if (nodeHashCode == timestampHashCode) {
					found = true;
				} else if (found) {
					final String nodeName = unsignedSignatureElement.getLocalName();
					if ("TimeStampValidationData".equals(nodeName)) {
						return unsignedSignatureElement;
					}
				}
			}
		}
		return null;
	}

	@Override
	public CommitmentType getCommitmentTypeIndication() {
		CommitmentType result = null;

		NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_COMMITMENT_IDENTIFICATION);
		if (nodeList != null && nodeList.getLength() > 0) {
			result = new CommitmentType();
			for (int ii = 0; ii < nodeList.getLength(); ii++) {
				result.addIdentifier(DomUtils.getValue(nodeList.item(ii), xPathQueryHolder.XPATH_COMITMENT_IDENTIFIERS));
			}
		}
		return result;
	}

	/**
	 * // TODO (11/09/2014): to be deleted, eu.europa.esig.dss.xades.validation.XAdESSignature#getReferences() to be
	 * used
	 *
	 * @return
	 */
	public List<Element> getSignatureReferences() {

		final NodeList list = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_REFERENCE);
		List<Element> references = new ArrayList<Element>(list.getLength());
		for (int ii = 0; ii < list.getLength(); ii++) {

			final Node node = list.item(ii);
			references.add((Element) node);
		}
		return references;
	}

	public List<Reference> getReferences() {
		return references;
	}

	/**
	 * @return
	 */
	public List<Element> getSignatureObjects() {

		final NodeList list = DomUtils.getNodeList(signatureElement, XPathQueryHolder.XPATH_OBJECT);
		final List<Element> references = new ArrayList<Element>(list.getLength());
		for (int ii = 0; ii < list.getLength(); ii++) {

			final Node node = list.item(ii);
			final Element element = (Element) node;
			if (DomUtils.getElement(element, xPathQueryHolder.XPATH__QUALIFYING_PROPERTIES_SIGNED_PROPERTIES) != null) {
				// ignore signed properties
				continue;
			}
			references.add(element);
		}
		return references;
	}

	/**
	 * This method allows to register a new {@code XPathQueryHolder}.
	 *
	 * @param xPathQueryHolder
	 *            {@code XPathQueryHolder} to register
	 */
	public void registerXPathQueryHolder(final XPathQueryHolder xPathQueryHolder) {
		xPathQueryHolders.add(xPathQueryHolder);
	}

	public Element getUnsignedSignaturePropertiesDom() {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
	}

	public Element getUnsignedPropertiesDom() {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_PROPERTIES);
	}

	public Element getQualifyingPropertiesDom() {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_QUALIFYING_PROPERTIES);
	}

}
