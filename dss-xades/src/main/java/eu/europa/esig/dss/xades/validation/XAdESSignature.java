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

import static eu.europa.esig.dss.xades.XPathQueryHolder.XMLE_ALGORITHM;
import static eu.europa.esig.dss.xades.XPathQueryHolder.XMLE_REFS_ONLY_TIME_STAMP;
import static eu.europa.esig.dss.xades.XPathQueryHolder.XMLE_SIGNATURE_TIME_STAMP;
import static eu.europa.esig.dss.xades.XPathQueryHolder.XMLE_SIG_AND_REFS_TIME_STAMP;

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
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.transform.stream.StreamSource;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.ReferenceNotInitializedException;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSNotETSICompliantException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.EncryptionAlgorithm;
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
import eu.europa.esig.dss.validation.OCSPRef;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.TimestampInclude;
import eu.europa.esig.dss.validation.TimestampReference;
import eu.europa.esig.dss.validation.TimestampReferenceCategory;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.ArchiveTimestampType;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;
import eu.europa.esig.dss.x509.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * Parse an XAdES signature structure. Note that for each signature to be validated a new instance of this object must
 * be created.
 *
 */
public class XAdESSignature extends DefaultAdvancedSignature {

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

	public static final String DEFAULT_TIMESTAMP_VALIDATION_CANONICALIZATION_METHOD = CanonicalizationMethod.INCLUSIVE;

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

		Init.init();

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
	 *            w3c.dom <ds:Signature> element
	 * @param certPool
	 *            can be null
	 */
	public XAdESSignature(final Element signatureElement, final CertificatePool certPool) {
		this(signatureElement, new ArrayList<XPathQueryHolder>() {
			{
				add(new XPathQueryHolder());
			}
		}, certPool);
	}

	/**
	 * The default constructor for XAdESSignature.
	 *
	 * @param signatureElement
	 *            w3c.dom <ds:Signature> element
	 * @param xPathQueryHolders
	 *            List of {@code XPathQueryHolder} to use when handling signature
	 * @param certPool
	 *            can be null
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
	 * This method returns the certificate pool used by this instance to handle encapsulated certificates.
	 *
	 * @return
	 */
	public CertificatePool getCertPool() {
		return certPool;
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

		final String xmlName = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_METHOD).getAttribute(XMLE_ALGORITHM);
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forXML(xmlName, null);
		if (signatureAlgorithm == null) {
			return null;
		}
		return signatureAlgorithm.getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		final String xmlName = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_METHOD).getAttribute(XMLE_ALGORITHM);
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forXML(xmlName, null);
		if (signatureAlgorithm == null) {
			return null;
		}
		return signatureAlgorithm.getDigestAlgorithm();
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
		if (length == 0) {
			final CertificateValidity theCertificateValidity = candidates.getTheCertificateValidity();
			final CertificateToken certificateToken = theCertificateValidity == null ? null : theCertificateValidity.getCertificateToken();
			// The check need to be done at the level of KeyInfo
			for (final Reference reference : references) {

				final String uri = reference.getURI();
				if (!uri.startsWith("#")) {
					continue;
				}

				final String id = uri.substring(1);
				final Element element = signatureElement.getOwnerDocument().getElementById(id);
				// final Element element =
				// DomUtils.getElement(signatureElement, "");
				if (!hasSignatureAsParent(element)) {

					continue;
				}
				if ((certificateToken != null) && id.equals(certificateToken.getXmlId())) {

					theCertificateValidity.setSigned(element.getNodeName());
					return;
				}
			}
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
				final String xmlAlgorithmName = digestMethodElement.getAttribute(XMLE_ALGORITHM);
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
				certificateValidity.setDigestEqual(false);
				BigInteger serialNumber = new BigInteger("0");
				if (Arrays.equals(digest, storedBase64DigestValue)) {
					X500Principal issuerName = null;
					if (isEn319132) {
						final Element issuerNameEl = DomUtils.getElement(element, xPathQueryHolder.XPATH__X509_ISSUER_V2);
						if (issuerNameEl != null) {
							final String textContent = issuerNameEl.getTextContent();

							ASN1InputStream is = null;
							GeneralName name = null;
							ASN1Integer serial = null;
							try {
								is = new ASN1InputStream(Utils.fromBase64(textContent));
								ASN1Sequence seq = (ASN1Sequence) is.readObject();
								ASN1Sequence obj = (ASN1Sequence) seq.getObjectAt(0);
								name = GeneralName.getInstance(obj.getObjectAt(0));
								serial = (ASN1Integer) seq.getObjectAt(1);
							} catch (IOException e) {
								LOG.error("Unable to decode textContent " + textContent + " : " + e.getMessage(), e);
							} finally {
								Utils.closeQuietly(is);
							}

							try {
								issuerName = new X500Principal(name.getName().toASN1Primitive().getEncoded());
							} catch (Exception e) {
								LOG.error("Unable to decode X500Principal : " + e.getMessage(), e);
							}

							try {
								serialNumber = serial.getValue();
							} catch (Exception e) {
								LOG.error("Unable to decode serialNumber : " + e.getMessage(), e);
							}

						}
					} else {
						final Element issuerNameEl = DomUtils.getElement(element, xPathQueryHolder.XPATH__X509_ISSUER_NAME);
						// This can be allayed when the distinguished name is not
						// correctly encoded
						// final String textContent =
						// DSSUtils.unescapeMultiByteUtf8Literals(issuerNameEl.getTextContent());
						final String textContent = issuerNameEl.getTextContent();

						issuerName = DSSUtils.getX500PrincipalOrNull(textContent);

						final Element serialNumberEl = DomUtils.getElement(element, xPathQueryHolder.XPATH__X509_SERIAL_NUMBER);
						final String serialNumberText = serialNumberEl.getTextContent();
						// serial number can contain leading and trailing whitespace.
						serialNumber = new BigInteger(serialNumberText.trim());
					}
					final X500Principal candidateIssuerName = certificateToken.getIssuerX500Principal();

					final boolean issuerNameMatches = DSSUtils.x500PrincipalAreEquals(candidateIssuerName, issuerName);
					if (!issuerNameMatches) {
						final String c14nCandidateIssuerName = candidateIssuerName.getName(X500Principal.CANONICAL);
						LOG.info("candidateIssuerName: " + c14nCandidateIssuerName);
						final String c14nIssuerName = issuerName == null ? "" : issuerName.getName(X500Principal.CANONICAL);
						LOG.info("issuerName         : " + c14nIssuerName);
					}

					final BigInteger candidateSerialNumber = certificateToken.getSerialNumber();
					final boolean serialNumberMatches = candidateSerialNumber.equals(serialNumber);

					certificateValidity.setDigestEqual(true);
					certificateValidity.setSerialNumberEqual(serialNumberMatches);
					certificateValidity.setDistinguishedNameEqual(issuerNameMatches);
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

	/**
	 * Checks if the given {@code Element} has as parent the current signature. This is the security check.
	 *
	 * @param element
	 *            the element to be checked (can be null)
	 * @return true if the given element has as parent the current signature element, false otherwise
	 */
	private boolean hasSignatureAsParent(final Element element) {

		if (element == null) {
			return false;
		}
		Node node = element;
		String nodeName = node.getNodeName();
		if (XPathQueryHolder.XMLE_X509CERTIFICATE.equals(nodeName)) {

			node = node.getParentNode();
			if (node == null) {
				return false;
			}
			nodeName = node.getNodeName();

		}
		if (XPathQueryHolder.XMLE_X509DATA.equals(nodeName)) {

			node = node.getParentNode();
			if (node == null) {
				return false;
			}
			nodeName = node.getNodeName();
		}
		if (XPathQueryHolder.XMLE_KEYINFO.equals(nodeName)) {

			node = node.getParentNode();
			if (node == null) {
				return false;
			}
		}
		if (!node.equals(signatureElement)) {
			return false;
		}
		return true;
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
				String policyIdString = policyId.getTextContent();
				// urn:oid:1.2.3 --> 1.2.3
				String policyUrlString = null;
				if (policyIdString.indexOf(':') >= 0) {
					policyIdString = policyIdString.substring(policyIdString.lastIndexOf(':') + 1);
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
					signaturePolicy.setUrl(policyUrlString);
				}
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

		return "text/xml";
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

			// TODO (09/11/2014): The error message must be propagated to the
			// validation report
			LOG.warn("The timestamp (" + timestampType.name() + ") cannot be extracted from the signature!");
			return null;

		}
		final String base64EncodedTimestamp = timestampTokenNode.getTextContent();
		final TimeStampToken timeStampToken = createTimeStampToken(base64EncodedTimestamp);
		final TimestampToken timestampToken = new TimestampToken(timeStampToken, timestampType, certPool);
		timestampToken.setHashCode(timestampElement.hashCode());
		setTimestampCanonicalizationMethod(timestampElement, timestampToken);

		// TODO: timestampToken.setIncludes(element.getIncludes)...
		// final NodeList includes =
		// timestampTokenNode.getElementsByTagName("Include");
		// for (int i = 0; i < includes.getLength(); ++i) {
		// timestampToken.getTimestampIncludes().add(new
		// TimestampInclude(includes.item(i).getBaseURI(),
		// includes.item(i).getAttributes()));
		// }
		return timestampToken;
	}

	/**
	 * This method generates a bouncycastle {@code TimeStampToken} based on base 64 encoded {@code String}.
	 *
	 * @param base64EncodedTimestamp
	 * @return bouncycastle {@code TimeStampToken}
	 * @throws DSSException
	 */
	private TimeStampToken createTimeStampToken(final String base64EncodedTimestamp) throws DSSException {
		try {
			final byte[] tokenBytes = Utils.fromBase64(base64EncodedTimestamp);
			final CMSSignedData signedData = new CMSSignedData(tokenBytes);
			return new TimeStampToken(signedData);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public Element getSignatureValue() {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_VALUE);
	}

	public Element getObject() {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_OBJECT);
	}

	/**
	 * This method returns the list of ds:Object elements for the current signature element.
	 *
	 * @return
	 */
	public NodeList getObjects() {
		return DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_OBJECT);
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
	 * @return
	 */
	public boolean hasBProfile() {
		return DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_SIGNED_SIGNATURE_PROPERTIES);
	}

	/**
	 * Checks the presence of SignatureTimeStamp segment in the signature, what is the proof -T profile existence
	 *
	 * @return
	 */
	public boolean hasTProfile() {
		return DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_TIMESTAMP);
	}

	/**
	 * Checks the presence of CompleteCertificateRefs & CompleteRevocationRefs segments in the signature, what is the
	 * proof -C profile existence
	 *
	 * @return
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
	 * Checks the presence of CertificateValues and RevocationValues segments in the signature, what is the proof -LT
	 * (or -XL) profile existence
	 *
	 * @return true if -LT (or -XL) extension is present
	 */
	public boolean hasLTProfile() {
		final boolean certValues = DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_CERTIFICATE_VALUES);

		final boolean revocationValues = DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_REVOCATION_VALUES);
		boolean notEmptyCRL = DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_ENCAPSULATED_CRL_VALUES);
		boolean notEmptyOCSP = DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_OCSP_VALUES_ENCAPSULATED_OCSP);

		boolean isLTProfile = revocationValues && (notEmptyCRL || notEmptyOCSP);
		if (!isLTProfile && certValues) {
			isLTProfile = hasTProfile();
		}

		return isLTProfile;
		// return certValues || (revocationValues && (notEmptyCRL || notEmptyOCSP));
	}

	/**
	 * Checks the presence of CertificateValues and RevocationValues segments in the signature, what is the proof -LTA
	 * (or -A) profile existence
	 *
	 * @return true if -LTA (or -A) extension is present
	 */
	public boolean hasLTAProfile() {
		final boolean archiveTimestamp = DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_ARCHIVE_TIMESTAMP);
		final boolean archiveTimestamp141 = DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_ARCHIVE_TIMESTAMP_141);
		final boolean archiveTimestampV2 = DomUtils.isNotEmpty(signatureElement, xPathQueryHolder.XPATH_ARCHIVE_TIMESTAMP_V2);
		return archiveTimestamp || archiveTimestamp141 || archiveTimestampV2;
	}

	/**
	 * Utility method to add content timestamps.
	 *
	 * @param timestampTokens
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
			// TODO : Strange code
			if (timestampToken == null) {
				continue;
			}
			if (timestampToken.getTimestampIncludes() == null) {
				timestampToken.setTimestampIncludes(new ArrayList<TimestampInclude>());
			}
			final NodeList timestampIncludes = DomUtils.getNodeList(element, xPathQueryHolder.XPATH__INCLUDE);
			for (int jj = 0; jj < timestampIncludes.getLength(); jj++) {

				final Element include = (Element) timestampIncludes.item(jj);
				final String uri = include.getAttribute("URI").substring(1); // '#'
				// is
				// removed
				timestampToken.getTimestampIncludes().add(new TimestampInclude(uri, include.getAttribute("referencedData")));
			}
			timestampTokens.add(timestampToken);
		}
	}

	@Override
	public byte[] getContentTimestampData(final TimestampToken timestampToken) {

		switch (timestampToken.getTimeStampType()) {
		case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
			return getIndividualDataObjectsTimestampData(timestampToken);
		case ALL_DATA_OBJECTS_TIMESTAMP:
			return getAllDataObjectsTimestampData(timestampToken);
		default:
			return null;
		}
	}

	/**
	 * See ETSI TS 101 903 v1.4.1, clause G.2.2.16.1.2
	 *
	 * @param timestampToken
	 * @return
	 */
	public byte[] getIndividualDataObjectsTimestampData(final TimestampToken timestampToken) {

		// TODO: check whether a warning would be more appropriate
		if (!checkTimestampTokenIncludes(timestampToken)) {
			throw new DSSException("The Included referencedData attribute is either not present or set to false!");
		}
		if (references.size() == 0) {
			throw new DSSException("The method 'checkSignatureIntegrity' must be invoked first!");
		}
		// get first include element
		// check coherence of the value of the not-fragment part of the URI
		// within its URI attribute according to the rules stated in 7.1.4.3.1
		// de-reference the URI according to the rules in 7.1.4.3.1
		// check that retrieved element is actually a ds:Reference element of
		// the ds:SignedInfo of the qualified signature and that its Type
		// attribute is not SignedProperties
		// if result is node-set, canonicalize it using the indicated
		// canonicalizationMethod element of the property || use standard canon.
		// method
		// concatenate the resulting bytes in an octet stream
		// repeat for all subsequent include elements, in order of appearance,
		// within the time-stamp container
		// return digest of resulting byte stream using the algorithm indicated
		// in the time-stamp token

		// get include elements from signature
		List<TimestampInclude> includes = timestampToken.getTimestampIncludes();

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		for (TimestampInclude include : includes) {
			// retrieve reference element
			// -> go through references and check for one whose URI matches the
			// URI of include
			for (final Reference reference : references) {
				String id = include.getURI();

				if (reference.getId().equals(id)) {
					try {
						final byte[] referencedBytes = reference.getReferencedBytes();
						outputStream.write(referencedBytes);
					} catch (IOException e) {
						throw new DSSException(e);
					} catch (ReferenceNotInitializedException e) {
						throw new DSSException(e);
					} catch (XMLSignatureException e) {
						throw new DSSException(e);
					}
				}
			}
		}
		byte[] octetStream = outputStream.toByteArray();
		return octetStream;
	}

	/**
	 * See ETSI TS 101 903 v1.4.1, clause G.2.2.16.1.1
	 *
	 * Retrieves the data from {@code TimeStampToken} of type AllDataObjectsTimestampData
	 *
	 * @param timestampToken
	 * @return a {@code byte} array containing the concatenated data from all reference elements of type differing from
	 *         SignedProperties
	 */
	public byte[] getAllDataObjectsTimestampData(final TimestampToken timestampToken) {

		// TODO: check whether a warning would be more appropriate
		if (!checkTimestampTokenIncludes(timestampToken)) {
			throw new DSSException("The Included referencedData attribute is either not present or set to false!");
		}
		if (references.size() == 0) {
			throw new DSSException("The method 'checkSignatureIntegrity' must be invoked first!");
		}
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		for (final Reference reference : references) {

			// Take, the first ds:Reference element within ds:SignedInfo if and
			// only if the Type attribute does not
			// have the value "http://uri.etsi.org/01903#SignedProperties".
			if (!xPathQueryHolder.XADES_SIGNED_PROPERTIES.equals(reference.getType())) {

				try {

					final byte[] referencedBytes = reference.getReferencedBytes();
					outputStream.write(referencedBytes);
				} catch (IOException e) {
					throw new DSSException(e);
				} catch (ReferenceNotInitializedException e) {
					throw new DSSException(e);
				} catch (XMLSignatureException e) {
					throw new DSSException(e);
				}
			}
		}
		// compute digest of resulting octet stream using algorithm indicated in
		// the time-stamp token
		// -> digest is computed in TimestampToken verification/match
		// return the computed digest
		byte[] toTimestampBytes = outputStream.toByteArray();
		if (LOG.isTraceEnabled()) {
			LOG.trace("AllDataObjectsTimestampData bytes: " + new String(toTimestampBytes));
		}
		return toTimestampBytes;
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
	 * @retun
	 */
	public boolean checkTimestampTokenIncludes(final TimestampToken timestampToken) {

		final List<TimestampInclude> timestampIncludes = timestampToken.getTimestampIncludes();
		for (final TimestampInclude timestampInclude : timestampIncludes) {
			if (!timestampInclude.isReferencedData()) {
				return false;
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
			if (node.getNodeType() != Node.ELEMENT_NODE) { // This can happened
				// when there is a
				// blank line
				// between tags.
				continue;
			}
			TimestampToken timestampToken;
			final String localName = node.getLocalName();
			if (XMLE_SIGNATURE_TIME_STAMP.equals(localName)) {

				timestampToken = makeTimestampToken((Element) node, TimestampType.SIGNATURE_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				timestampToken.setTimestampedReferences(getSignatureTimestampedReferences());
				signatureTimestamps.add(timestampToken);
			} else if (XMLE_REFS_ONLY_TIME_STAMP.equals(localName) || XPathQueryHolder.XMLE_REFS_ONLY_TIME_STAMP_V2.equals(localName)) {

				timestampToken = makeTimestampToken((Element) node, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				timestampToken.setTimestampedReferences(getTimestampedReferences());
				refsOnlyTimestamps.add(timestampToken);
			} else if (XMLE_SIG_AND_REFS_TIME_STAMP.equals(localName) || XPathQueryHolder.XMLE_SIG_AND_REFS_TIME_STAMP_V2.equals(localName)) {

				timestampToken = makeTimestampToken((Element) node, TimestampType.VALIDATION_DATA_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				final List<TimestampReference> references = getSignatureTimestampedReferences();
				references.addAll(getTimestampedReferences());
				timestampToken.setTimestampedReferences(references);
				sigAndRefsTimestamps.add(timestampToken);
			} else if (isArchiveTimestamp(localName)) {

				timestampToken = makeTimestampToken((Element) node, TimestampType.ARCHIVE_TIMESTAMP);
				if (timestampToken == null) {
					continue;
				}
				final ArchiveTimestampType archiveTimestampType = getArchiveTimestampType(node, localName);
				timestampToken.setArchiveTimestampType(archiveTimestampType);

				final List<TimestampReference> references = getSignatureTimestampedReferences();
				for (final String timestampId : timestampedTimestamps) {
					references.add(new TimestampReference(timestampId, TimestampReferenceCategory.TIMESTAMP));
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

		if (XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP_V2.equals(localName)) {
			return ArchiveTimestampType.XAdES_141_V2;
		} else if (XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP.equals(localName)) {

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

	private void setTimestampCanonicalizationMethod(final Element timestampElement, final TimestampToken timestampToken) {

		final Element canonicalizationMethodElement = DomUtils.getElement(timestampElement, xPathQueryHolder.XPATH__CANONICALIZATION_METHOD);
		String canonicalizationMethod = DEFAULT_TIMESTAMP_VALIDATION_CANONICALIZATION_METHOD;
		if (canonicalizationMethodElement != null) {
			canonicalizationMethod = canonicalizationMethodElement.getAttribute(XMLE_ALGORITHM);
		}
		timestampToken.setCanonicalizationMethod(canonicalizationMethod);
	}

	/*
	 * Returns an unmodifiable list of all certificate tokens encapsulated in the signature
	 * 
	 * @see eu.europa.esig.dss.validation.AdvancedSignature#getCertificates()
	 */
	@Override
	public List<CertificateToken> getCertificates() {

		return getCertificateSource().getCertificates();
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
		final Document document = signatureElement.getOwnerDocument();
		final Element rootElement = document.getDocumentElement();

		DSSXMLUtils.setIDIdentifier(rootElement);
		DSSXMLUtils.recursiveIdBrowse(rootElement);
		try {

			final XMLSignature santuarioSignature = new XMLSignature(signatureElement, "");
			santuarioSignature.addResourceResolver(new XPointerResourceResolver(signatureElement));
			santuarioSignature.addResourceResolver(new OfflineResolver(detachedContents, getDigestAlgorithm()));

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
					LOG.debug("Exception while probing candidate certificate as signing certificate: " + e.getMessage());
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
			final SignedInfo signedInfo = santuarioSignature.getSignedInfo();
			final int length = signedInfo.getLength();

			boolean referenceDataFound = length > 0;
			boolean referenceDataHashValid = length > 0;

			boolean foundSignedProperties = false;
			for (int ii = 0; ii < length; ii++) {
				final Reference reference = signedInfo.item(ii);
				if (xPathQueryHolder.XADES_SIGNED_PROPERTIES.equals(reference.getType())) {
					foundSignedProperties = true;
				}
				if (!coreValidity) {
					referenceDataHashValid = referenceDataHashValid && reference.verify();
				}
				references.add(reference);
			}

			// 1 reference for SignedProperties + 1 reference / signed object
			referenceDataFound = referenceDataFound && foundSignedProperties;

			signatureCryptographicVerification.setReferenceDataFound(referenceDataFound);
			signatureCryptographicVerification.setReferenceDataIntact(referenceDataHashValid);
			signatureCryptographicVerification.setSignatureIntact(coreValidity);
		} catch (Exception e) {

			LOG.error(e.getMessage());
			LOG.debug(e.getMessage(), e);
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
			if (certificateValidityList.size() == 0) {

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

			String xmlName = digestAlgorithmEl.getAttribute(XMLE_ALGORITHM);
			genericCertId.setDigestAlgorithm(DigestAlgorithm.forXML(xmlName));

			genericCertId.setDigestValue(Utils.fromBase64(digestValueEl.getTextContent()));
			certIds.add(genericCertId);
		}

		return certIds;

	}

	@Override
	public List<CRLRef> getCRLRefs() {
		final List<CRLRef> certIds = new ArrayList<CRLRef>();
		final Element signingCertEl = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_REVOCATION_CRL_REFS);
		if (signingCertEl != null) {

			final NodeList crlRefNodes = DomUtils.getNodeList(signingCertEl, xPathQueryHolder.XPATH__CRL_REF);
			for (int i = 0; i < crlRefNodes.getLength(); i++) {

				final Element certId = (Element) crlRefNodes.item(i);
				final Element digestAlgorithmEl = DomUtils.getElement(certId, xPathQueryHolder.XPATH__DAAV_DIGEST_METHOD);
				final Element digestValueEl = DomUtils.getElement(certId, xPathQueryHolder.XPATH__DAAV_DIGEST_VALUE);

				final String xmlName = digestAlgorithmEl.getAttribute(XMLE_ALGORITHM);
				final DigestAlgorithm digestAlgo = DigestAlgorithm.forXML(xmlName);

				final CRLRef ref = new CRLRef(digestAlgo, Utils.fromBase64(digestValueEl.getTextContent()));
				certIds.add(ref);
			}
		}
		return certIds;
	}

	@Override
	public List<OCSPRef> getOCSPRefs() {
		final List<OCSPRef> certIds = new ArrayList<OCSPRef>();
		final Element signingCertEl = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_OCSP_REFS);
		if (signingCertEl != null) {

			final NodeList ocspRefNodes = DomUtils.getNodeList(signingCertEl, xPathQueryHolder.XPATH__OCSPREF);
			for (int i = 0; i < ocspRefNodes.getLength(); i++) {

				final Element certId = (Element) ocspRefNodes.item(i);
				final Element digestAlgorithmEl = DomUtils.getElement(certId, xPathQueryHolder.XPATH__DAAV_DIGEST_METHOD);
				final Element digestValueEl = DomUtils.getElement(certId, xPathQueryHolder.XPATH__DAAV_DIGEST_VALUE);

				if ((digestAlgorithmEl == null) || (digestValueEl == null)) {
					throw new DSSNotETSICompliantException(DSSNotETSICompliantException.MSG.XADES_DIGEST_ALG_AND_VALUE_ENCODING);
				}

				final String xmlName = digestAlgorithmEl.getAttribute(XMLE_ALGORITHM);
				final DigestAlgorithm digestAlgo = DigestAlgorithm.forXML(xmlName);

				final String digestValue = digestValueEl.getTextContent();
				final byte[] base64EncodedDigestValue = Utils.fromBase64(digestValue);
				final OCSPRef ocspRef = new OCSPRef(digestAlgo, base64EncodedDigestValue, false);
				certIds.add(ocspRef);
			}
		}
		return certIds;
	}

	@Override
	public byte[] getSignatureTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) {
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try {

			writeCanonicalizedValue(xPathQueryHolder.XPATH_SIGNATURE_VALUE, canonicalizationMethod, buffer);
			if (LOG.isTraceEnabled()) {
				LOG.trace("Signature timestamp: canonicalization method  --> {}", canonicalizationMethod);
				LOG.trace("                   : canonicalized string     --> {}", buffer.toString());
			}
		} catch (IOException e) {
			throw new DSSException("Error when computing the SignatureTimestamp", e);
		}
		return buffer.toByteArray();
	}

	@Override
	public byte[] getTimestampX1Data(final TimestampToken timestampToken, String canonicalizationMethod) {

		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try {

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
			if (LOG.isTraceEnabled()) {
				LOG.trace("X1Timestamp (SigAndRefsTimeStamp) canonicalised string:\n" + buffer.toString());
			}
			return buffer.toByteArray();
		} catch (IOException e) {
			throw new DSSException("Error when computing the SigAndRefsTimeStamp (X1Timestamp)", e);
		}
	}

	@Override
	public byte[] getTimestampX2Data(final TimestampToken timestampToken, String canonicalizationMethod) {

		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try {

			writeCanonicalizedValue(xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS, canonicalizationMethod, buffer);
			writeCanonicalizedValue(xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS, canonicalizationMethod, buffer);
			if (LOG.isTraceEnabled()) {
				LOG.trace("TimestampX2Data (RefsOnlyTimeStamp) canonicalised string:\n" + buffer.toString());
			}
			return buffer.toByteArray();
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
		 */
		try {

			/**
			 * 1) Initialize the final octet stream as an empty octet stream.
			 */
			final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

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

				try {

					String uri = reference.getURI();
					if (uri.startsWith("#")) {
						uri = uri.substring(1);
					}
					referenceURIs.add(uri);
					final byte[] bytes = reference.getReferencedBytes();
					Utils.write(bytes, buffer);
				} catch (XMLSignatureException e) {
					throw new DSSException(e);
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
				if (node.getNodeType() != Node.ELEMENT_NODE) { // This can
					// happened when
					// there is a
					// blank line
					// between tags.
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
				if (isArchiveTimestamp(localName)) {

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
					canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, node);
				}
				if (LOG.isTraceEnabled()) {
					LOG.trace(localName + ": Canonicalization: " + canonicalizationMethod);
					LOG.trace(new String(canonicalizedValue) + "\n");
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
						if ("ID".equals(nodeName.toUpperCase())) {
							id = item.getNodeValue();
							break;
						}
					}
					final boolean contains = referenceURIs.contains(id);
					if (contains) {
						continue;
					}
				}
				byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, node);
				buffer.write(canonicalizedValue);
			}
			final byte[] bytes = buffer.toByteArray();
			return bytes;
		} catch (IOException e) {
			throw new DSSException("Error when computing the archive data", e);
		}
	}

	private void writeCanonicalizedValue(final String xPathString, final String canonicalizationMethod, final ByteArrayOutputStream buffer) throws IOException {

		final Element element = DomUtils.getElement(signatureElement, xPathString);
		if (element != null) {

			final byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, element);
			buffer.write(canonicalizedValue);
		}
	}

	private boolean isArchiveTimestamp(final String localName) {
		return XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP.equals(localName) || XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP_V2.equals(localName);
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
			break;
		case XAdES_BASELINE_LT:
			dataForLevelPresent &= hasLTProfile();
			break;
		case XAdES_BASELINE_T:
			dataForLevelPresent &= hasTProfile();
			break;
		case XAdES_BASELINE_B:
			dataForLevelPresent &= hasBProfile();
			break;
		case XAdES_X:
			dataForLevelPresent &= hasXProfile();
			break;
		case XAdES_C:
			dataForLevelPresent &= hasCProfile();
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
		return null;
	}

	@Override
	public CommitmentType getCommitmentTypeIndication() {
		return null;
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