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

package eu.europa.ec.markt.dss.validation102853.xades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
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
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNotETSICompliantException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.exception.DSSNullReturnedException;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.ArchiveTimestampType;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.DefaultAdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignaturePolicy;
import eu.europa.ec.markt.dss.validation102853.TimestampInclude;
import eu.europa.ec.markt.dss.validation102853.TimestampReference;
import eu.europa.ec.markt.dss.validation102853.TimestampReferenceCategory;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.bean.CandidatesForSigningCertificate;
import eu.europa.ec.markt.dss.validation102853.bean.CertificateValidity;
import eu.europa.ec.markt.dss.validation102853.bean.CertifiedRole;
import eu.europa.ec.markt.dss.validation102853.bean.CommitmentType;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateRef;
import eu.europa.ec.markt.dss.validation102853.crl.CRLRef;
import eu.europa.ec.markt.dss.validation102853.crl.OfflineCRLSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.OCSPRef;
import eu.europa.ec.markt.dss.validation102853.ocsp.OfflineOCSPSource;
import eu.europa.ec.markt.dss.validation102853.toolbox.XPointerResourceResolver;

/**
 * Parse an XAdES signature structure. Note that for each signature to be validated a new instance of this object must be created.
 *
 * @version $Revision: 1825 $ - $Date: 2013-03-28 15:57:37 +0100 (Thu, 28 Mar 2013) $
 */

public class XAdESSignature extends DefaultAdvancedSignature {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESSignature.class);

	/**
	 * This array contains all the XAdES signatures levels
	 * TODO: do not return redundant levels.
	 */
	private static SignatureLevel[] signatureLevels = new SignatureLevel[]{SignatureLevel.XML_NOT_ETSI, SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T, SignatureLevel.XAdES_C, SignatureLevel.XAdES_X, SignatureLevel.XAdES_XL, SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA, SignatureLevel.XAdES_A};

	/**
	 * This variable contains the list of {@code XPathQueryHolder} adapted to the specific signature schema.
	 */
	private final List<XPathQueryHolder> xPathQueryHolders;

	/**
	 * This variable contains the XPathQueryHolder adapted to the signature schema.
	 */
	protected XPathQueryHolder xPathQueryHolder;

	/**
	 * This is the default canonicalization method for XMLDSIG used for timestamps. Another complication arises because of the way that the default canonicalization algorithm
	 * handles namespace declarations; frequently a signed XML document needs to be embedded in another document; in this case the original canonicalization algorithm will not
	 * yield the same result as if the document is treated alone. For this reason, the so-called Exclusive Canonicalization, which serializes XML namespace declarations
	 * independently of the surrounding XML, was created.
	 */
	public static final String DEFAULT_TIMESTAMP_CREATION_CANONICALIZATION_METHOD = CanonicalizationMethod.EXCLUSIVE;
	public static final String DEFAULT_TIMESTAMP_VALIDATION_CANONICALIZATION_METHOD = CanonicalizationMethod.INCLUSIVE;

	private final Element signatureElement;

	/**
	 * Indicates the id of the signature. If not existing this attribute is auto calculated.
	 */
	private String signatureId;

	private XAdESCertificateSource certificatesSource;

	/**
	 * This variable contains all references found within the signature. They are extracted when the method {@code checkSignatureIntegrity} is called.
	 */
	private transient List<Reference> references = new ArrayList<Reference>();

	/**
	 * This list represents all digest algorithms used to calculate the digest values of certificates.
	 */
	private Set<DigestAlgorithm> usedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();

	static {

		Init.init();

		/**
		 * Adds the support of ECDSA_RIPEMD160 for XML signature. Used by AT.
		 * The BC provider must be previously added.
		 */
		//		final JCEMapper.Algorithm algorithm = new JCEMapper.Algorithm("", SignatureAlgorithm.ECDSA_RIPEMD160.getJCEId(), "Signature");
		//		final String xmlId = SignatureAlgorithm.ECDSA_RIPEMD160.getXMLId();
		//		JCEMapper.register(xmlId, algorithm);
		//		try {
		//			org.apache.xml.security.algorithms.SignatureAlgorithm.register(xmlId, SignatureECDSARIPEMD160.class);
		//		} catch (Exception e) {
		//			LOG.error("ECDSA_RIPEMD160 algorithm initialisation failed.", e);
		//		}

		/**
		 * Adds the support of not standard algorithm name: http://www.w3.org/2001/04/xmldsig-more/rsa-ripemd160. Used by some AT signature providers.
		 * The BC provider must be previously added.
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
	 * @param signatureElement w3c.dom <ds:Signature> element
	 * @param certPool         can be null
	 */
	public XAdESSignature(final Element signatureElement, final CertificatePool certPool) {

		this(signatureElement, (new ArrayList<XPathQueryHolder>() {{
			add(new XPathQueryHolder());
		}}), certPool);
	}

	/**
	 * The default constructor for XAdESSignature.
	 *
	 * @param signatureElement  w3c.dom <ds:Signature> element
	 * @param xPathQueryHolders List of {@code XPathQueryHolder} to use when handling signature
	 * @param certPool          can be null
	 */
	public XAdESSignature(final Element signatureElement, final List<XPathQueryHolder> xPathQueryHolders, final CertificatePool certPool) throws DSSNullException {

		super(certPool);
		if (signatureElement == null) {

			throw new DSSNullException(Element.class, "signatureElement");
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
	 * This method sets the namespace which will determinate the {@code XPathQueryHolder} to use. The content of the Transform element is ignored.
	 *
	 * @param element
	 */
	public void recursiveNamespaceBrowser(final Element element) {

		for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {

			final Node node = element.getChildNodes().item(ii);
			if (node.getNodeType() == Node.ELEMENT_NODE) {

				final Element childElement = (Element) node;
				final String namespaceURI = childElement.getNamespaceURI();
				// final String tagName = childElement.getTagName();
				final String localName = childElement.getLocalName();
				// final String nodeName = childElement.getNodeName();
				// System.out.println(tagName + "-->" + namespaceURI);
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

		final String xmlName = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_METHOD).getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forXML(xmlName, null);
		if (signatureAlgorithm == null) {
			return null;
		}
		return signatureAlgorithm.getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {

		final String xmlName = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_METHOD).getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
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
	 * This method resets the source of certificates. It must be called when any certificate is added to the KeyInfo or CertificateValues.
	 */
	public void resetSources() {

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

	@Override
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate() {

		if (candidatesForSigningCertificate != null) {
			return candidatesForSigningCertificate;
		}
		candidatesForSigningCertificate = new CandidatesForSigningCertificate();
		/**
		 * 5.1.4.1 XAdES processing<br>
		 * <i>Candidates for the signing certificate extracted from ds:KeyInfo element</i> shall be checked
		 * against all references present in the ds:SigningCertificate property, if present, since one of these
		 * references shall be a reference to the signing certificate.
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
		 * digests values of other certificates (that MAY form a chain up to the point of trust).
		 */

		final NodeList list = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNING_CERTIFICATE_CERT);
		final int length = list.getLength();
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
				// final Element element = DSSXMLUtils.getElement(signatureElement, "");
				if (!hasSignatureAsParent(element)) {

					continue;
				}
				if (certificateToken != null && id.equals(certificateToken.getXmlId())) {

					theCertificateValidity.setSigned(element.getNodeName());
					return;
				}
			}
		}
		// This Map contains the list of the references to the certificate which were already checked and which correspond to a certificate.
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
				final Element certDigestElement = DSSXMLUtils.getElement(element, xPathQueryHolder.XPATH__CERT_DIGEST);
				certificateValidity.setDigestPresent(certDigestElement != null);

				final Element digestMethodElement = DSSXMLUtils.getElement(certDigestElement, xPathQueryHolder.XPATH__DIGEST_METHOD);
				if (digestMethodElement == null) {
					continue;
				}
				final String xmlAlgorithmName = digestMethodElement.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
				// The default algorithm is used in case of bad encoded algorithm name
				final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(xmlAlgorithmName, DigestAlgorithm.SHA1);

				final Element digestValueElement = DSSXMLUtils.getElement(element, xPathQueryHolder.XPATH__CERT_DIGEST_DIGEST_VALUE);
				if (digestValueElement == null) {
					continue;
				}
				// That must be a binary comparison
				final byte[] storedBase64DigestValue = DSSUtils.base64StringToBase64Binary(digestValueElement.getTextContent());

				/**
				 * Step 1:<br>
				 * Take the first child of the property and check that the content of ds:DigestValue matches the
				 * result of digesting <i>the candidate for</i> the signing certificate with the algorithm indicated
				 * in ds:DigestMethod. If they do not match, take the next child and repeat this step until a matching
				 * child element has been found or all children of the element have been checked. If they do match,
				 * continue with step 2. If the last element is reached without finding any match, the validation of
				 * this property shall be taken as failed and INVALID/FORMAT_FAILURE is returned.
				 */
				final byte[] digest = DSSUtils.digest(digestAlgorithm, certificateToken.getEncoded());
				final byte[] recalculatedBase64DigestValue = DSSUtils.base64BinaryEncode(digest);
				certificateValidity.setDigestEqual(false);
				if (Arrays.equals(recalculatedBase64DigestValue, storedBase64DigestValue)) {

					final Element issuerNameEl = DSSXMLUtils.getElement(element, xPathQueryHolder.XPATH__X509_ISSUER_NAME);
					// This can be allayed when the distinguished name is not correctly encoded
					// final String textContent = DSSUtils.unescapeMultiByteUtf8Literals(issuerNameEl.getTextContent());
					final String textContent = issuerNameEl.getTextContent();
					final X500Principal issuerName = DSSUtils.getX500PrincipalOrNull(textContent);
					final X500Principal candidateIssuerName = certificateToken.getIssuerX500Principal();

					// final boolean issuerNameMatches = candidateIssuerName.equals(issuerName);
					final boolean issuerNameMatches = DSSUtils.equals(candidateIssuerName, issuerName);
					if (!issuerNameMatches) {

						final String c14nCandidateIssuerName = candidateIssuerName.getName(X500Principal.CANONICAL);
						LOG.info("candidateIssuerName: " + c14nCandidateIssuerName);
						final String c14nIssuerName = issuerName == null ? "" : issuerName.getName(X500Principal.CANONICAL);
						LOG.info("issuerName         : " + c14nIssuerName);
					}

					final Element serialNumberEl = DSSXMLUtils.getElement(element, xPathQueryHolder.XPATH__X509_SERIAL_NUMBER);
					final BigInteger serialNumber = new BigInteger(serialNumberEl.getTextContent());
					final BigInteger candidateSerialNumber = certificateToken.getSerialNumber();
					final boolean serialNumberMatches = candidateSerialNumber.equals(serialNumber);

					certificateValidity.setDigestEqual(true);
					certificateValidity.setSerialNumberEqual(serialNumberMatches);
					certificateValidity.setDistinguishedNameEqual(issuerNameMatches);
					// The certificate was identified
					alreadyProcessedElements.put(element, true);
					// If the signing certificate is not set yet then it must be done now. Actually if the signature is tempered then the method checkSignatureIntegrity cannot set the signing certificate.
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
	 * @param element the element to be checked (can be null)
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

		final Element signingTimeEl = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNING_TIME);
		if (signingTimeEl == null) {
			return null;
		}
		final String text = signingTimeEl.getTextContent();
		return DSSXMLUtils.getDate(text);
	}

	@Override
	public SignaturePolicy getPolicyId() {

		final Element policyIdentifier = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER);
		if (policyIdentifier != null) {

			// There is a policy
			final Element policyId = DSSXMLUtils.getElement(policyIdentifier, xPathQueryHolder.XPATH__POLICY_ID);
			if (policyId != null) {
				// Explicit policy
				final String policyIdString = policyId.getTextContent();
				final SignaturePolicy signaturePolicy = new SignaturePolicy(policyIdString);
				final Node policyDigestMethod = DSSXMLUtils.getNode(policyIdentifier, xPathQueryHolder.XPATH__POLICY_DIGEST_METHOD);
				final String policyDigestMethodString = policyDigestMethod.getTextContent();
				final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(policyDigestMethodString);
				signaturePolicy.setDigestAlgorithm(digestAlgorithm);
				final Element policyDigestValue = DSSXMLUtils.getElement(policyIdentifier, xPathQueryHolder.XPATH__POLICY_DIGEST_VALUE);
				final String digestValue = policyDigestValue.getTextContent().trim();
				signaturePolicy.setDigestValue(digestValue);
				return signaturePolicy;
			} else {
				// Implicit policy
				final Element signaturePolicyImplied = DSSXMLUtils.getElement(policyIdentifier, xPathQueryHolder.XPATH__SIGNATURE_POLICY_IMPLIED);
				if (signaturePolicyImplied != null) {
					return new SignaturePolicy();
				}
			}
		}
		return null;
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {

		final NodeList nodeList = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_PRODUCTION_PLACE);
		if (nodeList.getLength() == 0 || nodeList.item(0) == null) {

			return null;
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
			}
		}
		return signatureProductionPlace;
	}

	@Override
	public String[] getClaimedSignerRoles() {

		final NodeList nodeList = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CLAIMED_ROLE);
		if (nodeList.getLength() == 0) {

			return null;
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
		final NodeList nodeList = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CERTIFIED_ROLE);
		if (nodeList.getLength() == 0) {

			return null;
		}
		final List<CertifiedRole> roles = new ArrayList<CertifiedRole>();
		for (int ii = 0; ii < nodeList.getLength(); ii++) {

			final Element certEl = (Element) nodeList.item(ii);
			final String textContent = certEl.getTextContent();
			final X509Certificate x509Certificate = DSSUtils.loadCertificateFromBase64EncodedString(textContent);
			if (!roles.contains(x509Certificate)) {

				roles.add(new CertifiedRole());
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
	 * @param id            the DSS identifier of the timestamp
	 * @param element       contains the encapsulated timestamp
	 * @param timestampType {@code TimestampType}
	 * @return {@code TimestampToken} of the given type
	 * @throws DSSException
	 */
	private TimestampToken makeTimestampToken(int id, Element element, TimestampType timestampType) throws DSSException {

		final Element timestampTokenNode = DSSXMLUtils.getElement(element, xPathQueryHolder.XPATH__ENCAPSULATED_TIMESTAMP);
		if (timestampTokenNode == null) {

			// TODO (09/11/2014): The error message must be propagated to the validation report
			LOG.warn("The timestamp (" + timestampType.name() + ") cannot be extracted from the signature!");
			return null;

		}
		final String base64EncodedTimestamp = timestampTokenNode.getTextContent();
		final TimeStampToken timeStampToken = DSSASN1Utils.createTimeStampToken(base64EncodedTimestamp);
		final TimestampToken timestampToken = new TimestampToken(timeStampToken, timestampType, certPool);
		timestampToken.setDSSId(id);
		timestampToken.setHashCode(element.hashCode());

		//TODO: timestampToken.setIncludes(element.getIncludes)...
		final NodeList includes = timestampTokenNode.getElementsByTagName("Include");
		for (int i = 0; i < includes.getLength(); ++i) {
			//timestampToken.getTimestampIncludes().add(new TimestampInclude(includes.item(i).getBaseURI(), includes.item(i).getAttributes()));
		}
		return timestampToken;
	}

	public Node getSignatureValue() {

		return DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_VALUE);
	}

	public Element getObject() {

		return DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_OBJECT);
	}

	/**
	 * This method returns the list of ds:Object elements for the current signature element.
	 *
	 * @return
	 */
	public NodeList getObjects() {

		return DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_OBJECT);
	}

	public Element getCompleteCertificateRefs() {

		return DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS);
	}

	public Element getCompleteRevocationRefs() {

		return DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS);
	}

	public NodeList getSigAndRefsTimeStamp() {

		return DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIG_AND_REFS_TIMESTAMP);
	}

	public Element getCertificateValues() {

		return DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_CERTIFICATE_VALUES);
	}

	public Element getRevocationValues() {

		return DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_REVOCATION_VALUES);
	}

	/**
	 * Checks the presence of ... segment in the signature, what is the proof -B profile existence
	 *
	 * @return
	 */
	public boolean hasBProfile() {

		final int count = DSSXMLUtils.count(signatureElement, xPathQueryHolder.XPATH_COUNT_SIGNED_SIGNATURE_PROPERTIES);
		return count > 0;
	}

	/**
	 * Checks the presence of SignatureTimeStamp segment in the signature, what is the proof -T profile existence
	 *
	 * @return
	 */
	public boolean hasTProfile() {

		final int count = DSSXMLUtils.count(signatureElement, xPathQueryHolder.XPATH_COUNT_SIGNATURE_TIMESTAMP);
		return count > 0;
	}

	/**
	 * Checks the presence of CompleteCertificateRefs & CompleteRevocationRefs segments in the signature, what is the proof -C profile existence
	 *
	 * @return
	 */
	public boolean hasCProfile() {

		final boolean certRefs = DSSXMLUtils.count(signatureElement, xPathQueryHolder.XPATH_COUNT_COMPLETE_CERTIFICATE_REFS) > 0;
		final boolean revocationRefs = DSSXMLUtils.count(signatureElement, xPathQueryHolder.XPATH_COUNT_COMPLETE_REVOCATION_REFS) > 0;
		return certRefs || revocationRefs;
	}

	/**
	 * Checks the presence of SigAndRefsTimeStamp segment in the signature, what is the proof -X profile existence
	 *
	 * @return true if the -X extension is present
	 */
	public boolean hasXProfile() {

		boolean signAndRefs = DSSXMLUtils.count(signatureElement, xPathQueryHolder.XPATH_COUNT_SIG_AND_REFS_TIMESTAMP) > 0;
		return signAndRefs;
	}

	/**
	 * Checks the presence of CertificateValues and RevocationValues segments in the signature, what is the proof -XL profile existence
	 *
	 * @return true if -XL extension is present
	 */
	public boolean hasXLProfile() {

		final boolean certValues = DSSXMLUtils.count(signatureElement, xPathQueryHolder.XPATH_COUNT_CERTIFICATE_VALUES) > 0;
		final boolean revocationValues = DSSXMLUtils.count(signatureElement, xPathQueryHolder.XPATH_COUNT_REVOCATION_VALUES) > 0;
		return certValues || revocationValues;
	}

	/**
	 * Checks the presence of CertificateValues and RevocationValues segments in the signature, what is the proof -LT profile existence
	 *
	 * @return true if -LT extension is present
	 */
	public boolean hasLTProfile() {

		return hasXLProfile();
	}

	/**
	 * Checks the presence of CertificateValues and RevocationValues segments in the signature, what is the proof -A profile existence
	 *
	 * @return true if -A extension is present
	 */
	public boolean hasAProfile() {

		final boolean archiveTimestamp = DSSXMLUtils.count(signatureElement, xPathQueryHolder.XPATH_COUNT_ARCHIVE_TIMESTAMP) > 0;
		final boolean archiveTimestamp141 = DSSXMLUtils.count(signatureElement, xPathQueryHolder.XPATH_COUNT_ARCHIVE_TIMESTAMP_141) > 0;
		final boolean archiveTimestampV2 = DSSXMLUtils.count(signatureElement, xPathQueryHolder.XPATH_COUNT_ARCHIVE_TIMESTAMP_V2) > 0;
		return archiveTimestamp || archiveTimestamp141 || archiveTimestampV2;
	}

	/**
	 * Checks the presence of CertificateValues and RevocationValues segments in the signature, what is the proof -LTA profile existence
	 *
	 * @return true if -LTA extension is present
	 */
	public boolean hasLTAProfile() {

		return hasAProfile();
	}

	@Override
	public List<TimestampToken> getContentTimestamps() {

		if (contentTimestamps != null) {
			return contentTimestamps;
		}
		contentTimestamps = new ArrayList<TimestampToken>();
		final NodeList allDataObjectsTimestamps = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ALL_DATA_OBJECTS_TIMESTAMP);
		addContentTimestamps(contentTimestamps, allDataObjectsTimestamps);
		final NodeList individualDataObjectsTimestampsNodes = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
		addContentTimestamps(contentTimestamps, individualDataObjectsTimestampsNodes);
		return contentTimestamps;
	}

	/**
	 * Utility function - TODO: move in utils
	 *
	 * @param timestampTokens
	 * @param nodes
	 */
	public void addContentTimestamps(final List<TimestampToken> timestampTokens, final NodeList nodes) {

		int startIndex = timestampTokens.size();
		for (int ii = 0; ii < nodes.getLength(); ii++) {

			//TODO: should check with constant from XPathQueryHolder instead, and move to switch/case instead of ternary expression ?
			final Node node = nodes.item(ii);
			if (node.getNodeType() != Node.ELEMENT_NODE) {
				continue;
			}
			final Element element = (Element) node;
			final TimestampType type = "xades:AllDataObjectsTimeStamp"
				  .equals(element.getNodeName()) ? TimestampType.ALL_DATA_OBJECTS_TIMESTAMP : TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP;

			final TimestampToken timestampToken = makeTimestampToken(startIndex + ii, element, type);
			setTimestampCanonicalizationMethod(element, timestampToken);

			if (timestampToken != null) {
				if (timestampToken.getTimestampIncludes() == null) {
					timestampToken.setTimestampIncludes(new ArrayList<TimestampInclude>());
				}
				final NodeList includes = element.getChildNodes();
				final NodeList timestampIncludes = DSSXMLUtils.getNodeList(element, xPathQueryHolder.XPATH__INCLUDE);
				for (int jj = 0; jj < timestampIncludes.getLength(); jj++) {

					Element include = (Element) timestampIncludes.item(jj);
					String uri = include.getAttribute("URI").substring(1); //Dirty trick to remove the '#'... TODO: more elegant solution
					timestampToken.getTimestampIncludes().add(new TimestampInclude(uri, include.getAttribute("referencedData")));
				}
				timestampTokens.add(timestampToken);
			}
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

		//TODO: check whether a warning would be more appropriate
		if (!checkTimestampTokenIncludes(timestampToken)) {
			throw new DSSException("The Included referencedData attribute is either not present or set to false!");
		}
		if (references.size() == 0) {
			throw new DSSException("The method 'checkSignatureIntegrity' must be invoked first!");
		}
		//get first include element
		//check coherence of the value of the not-fragment part of the URI within its URI attribute according to the rules stated in 7.1.4.3.1
		//de-reference the URI according to the rules in 7.1.4.3.1
		//check that retrieved element is actually a ds:Reference element of the ds:SignedInfo of the qualified signature and that its Type attribute is not SignedProperties
		//if result is node-set, canonicalize it using the indicated canonicalizationMethod element of the property || use standard canon. method
		//concatenate the resulting bytes in an octet stream
		//repeat for all subsequent include elements, in order of appearance, within the time-stamp container
		//return digest of resulting byte stream using the algorithm indicated in the time-stamp token

		//get include elements from signature
		List<TimestampInclude> includes = timestampToken.getTimestampIncludes();

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		for (TimestampInclude include : includes) {
			//retrieve reference element
			//-> go through references and check for one whose URI matches the URI of include
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
	 * <p/>
	 * Retrieves the data from {@code TimeStampToken} of type AllDataObjectsTimestampData
	 *
	 * @param timestampToken
	 * @return a {@code byte} array containing the concatenated data from all reference elements of type differing from SignedProperties
	 */
	public byte[] getAllDataObjectsTimestampData(final TimestampToken timestampToken) {

		//TODO: check whether a warning would be more appropriate
		if (!checkTimestampTokenIncludes(timestampToken)) {
			throw new DSSException("The Included referencedData attribute is either not present or set to false!");
		}
		if (references.size() == 0) {
			throw new DSSException("The method 'checkSignatureIntegrity' must be invoked first!");
		}
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		for (final Reference reference : references) {

			// Take, the first ds:Reference element within ds:SignedInfo if and only if the Type attribute does not
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
		// compute digest of resulting octet stream using algorithm indicated in the time-stamp token
		// -> digest is computed in TimestampToken verification/match
		// return the computed digest
		byte[] toTimestampBytes = outputStream.toByteArray();
		if (LOG.isTraceEnabled()) {
			LOG.trace("AllDataObjectsTimestampData bytes: " + new String(toTimestampBytes));
		}
		return toTimestampBytes;
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() {

		if (signatureTimestamps == null) {

			signatureTimestamps = new ArrayList<TimestampToken>();
			final NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_TIMESTAMP);
			for (int ii = 0; ii < timestampsNodes.getLength(); ii++) {

				final Element timestampElement = (Element) timestampsNodes.item(ii);
				final TimestampToken timestampToken = makeTimestampToken(ii, timestampElement, TimestampType.SIGNATURE_TIMESTAMP);
				if (timestampToken != null) {

					setTimestampCanonicalizationMethod(timestampElement, timestampToken);

					final List<TimestampReference> references = new ArrayList<TimestampReference>();
					final TimestampReference signatureReference = new TimestampReference();
					signatureReference.setCategory(TimestampReferenceCategory.SIGNATURE);
					signatureReference.setSignatureId(getId());
					references.add(signatureReference);
					final NodeList list = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CERT_DIGEST);
					for (int jj = 0; jj < list.getLength(); jj++) {

						final Element element = (Element) list.item(jj);
						final TimestampReference signingCertReference = createCertificateTimestampReference(element);
						references.add(signingCertReference);
					}
					timestampToken.setTimestampedReferences(references);
					signatureTimestamps.add(timestampToken);
				}
			}
		}
		return signatureTimestamps;
	}

	/**
	 * This method ensures that all Include elements referring to the Reference elements have a referencedData attribute,
	 * which is set to "true".
	 * In case one of these Include elements has its referenceData set to false, the method returns false
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
	public List<TimestampToken> getTimestampsX1() {

		if (sigAndRefsTimestamps == null) {

			sigAndRefsTimestamps = new ArrayList<TimestampToken>();
			final NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIG_AND_REFS_TIMESTAMP);
			for (int ii = 0; ii < timestampsNodes.getLength(); ii++) {

				final Element timestampElement = (Element) timestampsNodes.item(ii);
				final TimestampToken timestampToken = makeTimestampToken(ii, timestampElement, TimestampType.VALIDATION_DATA_TIMESTAMP);
				if (timestampToken != null) {

					setTimestampCanonicalizationMethod(timestampElement, timestampToken);

					final List<TimestampReference> references = getTimestampedReferences();
					final TimestampReference signatureReference = new TimestampReference();
					signatureReference.setCategory(TimestampReferenceCategory.SIGNATURE);
					signatureReference.setSignatureId(getId());
					references.add(0, signatureReference);
					timestampToken.setTimestampedReferences(references);
					sigAndRefsTimestamps.add(timestampToken);
				}
			}
		}
		return sigAndRefsTimestamps;
	}

	@Override
	public List<TimestampToken> getTimestampsX2() {

		if (refsOnlyTimestamps == null) {

			refsOnlyTimestamps = new ArrayList<TimestampToken>();
			final NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_REFS_ONLY_TIMESTAMP);
			for (int ii = 0; ii < timestampsNodes.getLength(); ii++) {

				final Element timestampElement = (Element) timestampsNodes.item(ii);
				final TimestampToken timestampToken = makeTimestampToken(ii, timestampElement, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
				if (timestampToken != null) {

					setTimestampCanonicalizationMethod(timestampElement, timestampToken);

					timestampToken.setTimestampedReferences(getTimestampedReferences());
					refsOnlyTimestamps.add(timestampToken);
				}
			}
		}
		return refsOnlyTimestamps;
	}

	@Override
	public List<TimestampToken> getArchiveTimestamps() {

		if (archiveTimestamps == null) {

			archiveTimestamps = new ArrayList<TimestampToken>();
			final NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ARCHIVE_TIMESTAMP);
			addArchiveTimestamps(archiveTimestamps, timestampsNodes, ArchiveTimestampType.XAdES);
			final NodeList timestampsNodes141 = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ARCHIVE_TIMESTAMP_141);
			addArchiveTimestamps(archiveTimestamps, timestampsNodes141, ArchiveTimestampType.XAdES_141);
			final NodeList timestampsNodesV2 = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ARCHIVE_TIMESTAMP_V2);
			addArchiveTimestamps(archiveTimestamps, timestampsNodesV2, ArchiveTimestampType.XAdES_141_V2);
		}
		return archiveTimestamps;
	}

	private void addArchiveTimestamps(final List<TimestampToken> signatureTimestamps, final NodeList timestampsNodes, final ArchiveTimestampType archiveTimestampType) {

		for (int ii = 0; ii < timestampsNodes.getLength(); ii++) {

			final Element timestampElement = (Element) timestampsNodes.item(ii);
			final TimestampToken timestampToken = makeTimestampToken(ii, timestampElement, TimestampType.ARCHIVE_TIMESTAMP);
			if (timestampToken != null) {

				timestampToken.setArchiveTimestampType(archiveTimestampType);
				setTimestampCanonicalizationMethod(timestampElement, timestampToken);

				final List<TimestampReference> references = getTimestampedReferences();
				final TimestampReference signatureReference = new TimestampReference();
				signatureReference.setCategory(TimestampReferenceCategory.SIGNATURE);
				signatureReference.setSignatureId(getId());
				references.add(0, signatureReference);
				timestampToken.setTimestampedReferences(references);
				signatureTimestamps.add(timestampToken);
			}
		}
	}

	private void setTimestampCanonicalizationMethod(Element timestampElement, TimestampToken timestampToken) {
		final Element canonicalizationMethodElement = DSSXMLUtils.getElement(timestampElement, xPathQueryHolder.XPATH__CANONICALIZATION_METHOD);
		String canonicalizationMethod = DEFAULT_TIMESTAMP_VALIDATION_CANONICALIZATION_METHOD;
		if (canonicalizationMethodElement != null) {

			canonicalizationMethod = canonicalizationMethodElement.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
		}
		timestampToken.setCanonicalizationMethod(canonicalizationMethod);
	}

	/*
	 * Returns an unmodifiable list of all certificate tokens encapsulated in the signature
	 *
	 * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getCertificates()
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
	public SignatureCryptographicVerification checkSignatureIntegrity() {

		if (signatureCryptographicVerification != null) {
			return signatureCryptographicVerification;
		}
		signatureCryptographicVerification = new SignatureCryptographicVerification();
		final Document document = signatureElement.getOwnerDocument();
		final Element rootElement = document.getDocumentElement();

		DSSXMLUtils.setIDIdentifier(rootElement);
		DSSXMLUtils.recursiveIdBrowse(rootElement);
		try {

			final XMLSignature santuarioSignature = new XMLSignature(signatureElement, "");
			santuarioSignature.addResourceResolver(new XPointerResourceResolver(signatureElement));
			santuarioSignature.addResourceResolver(new OfflineResolver(detachedContents));

			boolean coreValidity = false;
			final List<CertificateValidity> certificateValidityList = getSigningCertificateValidityList(santuarioSignature, signatureCryptographicVerification,
				  providedSigningCertificateToken);
			for (final CertificateValidity certificateValidity : certificateValidityList) {

				try {

					final PublicKey publicKey = certificateValidity.getPublicKey();
					coreValidity = santuarioSignature.checkSignatureValue(publicKey);
					if (coreValidity) {

						candidatesForSigningCertificate.setTheCertificateValidity(certificateValidity);
						break;
					}
				} catch (XMLSignatureException e) {
					LOG.warn("Exception when validating signature: ", e);
					signatureCryptographicVerification.setErrorMessage(e.getMessage());
				}
			}
			final SignedInfo signedInfo = santuarioSignature.getSignedInfo();
			final int length = signedInfo.getLength();
			boolean referenceDataFound = length > 0;
			boolean referenceDataHashValid = length > 0;
			for (int ii = 0; ii < length; ii++) {

				final Reference reference = signedInfo.item(ii);
				if (!coreValidity) {

					referenceDataHashValid = referenceDataHashValid && reference.verify();
				}
				references.add(reference);
			}
			signatureCryptographicVerification.setReferenceDataFound(referenceDataFound);
			signatureCryptographicVerification.setReferenceDataIntact(referenceDataHashValid);
			signatureCryptographicVerification.setSignatureIntact(coreValidity);
		} catch (Exception e) {

			LOG.error(e.getMessage(), e);
			StackTraceElement[] stackTrace = e.getStackTrace();
			final String name = XAdESSignature.class.getName();
			int lineNumber = 0;
			for (int ii = 0; ii < stackTrace.length; ii++) {

				final String className = stackTrace[ii].getClassName();
				if (className.equals(name)) {

					lineNumber = stackTrace[ii].getLineNumber();
					break;
				}
			}
			signatureCryptographicVerification.setErrorMessage(e.getMessage() + "/ XAdESSignature/Line number/" + lineNumber);
		}
		return signatureCryptographicVerification;
	}

	/**
	 * This method returns a {@code List} of {@code SigningCertificateValidity} base on the certificates extracted from the signature or on the {@code
	 * providedSigningCertificateToken}.
	 * The field {@code candidatesForSigningCertificate} is instantiated in case where the signing certificated is provided.
	 *
	 * @param santuarioSignature         The object created tro validate the signature
	 * @param scv                        {@code SignatureCryptographicVerification} containing information on the signature validation
	 * @param providedSigningCertificate provided signing certificate: {@code CertificateToken}  @return
	 * @return the {@code List} of the {@code SigningCertificateValidity}
	 * @throws KeyResolverException
	 */
	private List<CertificateValidity> getSigningCertificateValidityList(final XMLSignature santuarioSignature, SignatureCryptographicVerification scv,
	                                                                           final CertificateToken providedSigningCertificate) throws KeyResolverException {

		List<CertificateValidity> certificateValidityList;
		if (providedSigningCertificate == null) {

			// To determine the signing certificate it is necessary to browse through all candidates extracted from the signature.
			final CandidatesForSigningCertificate candidates = getCandidatesForSigningCertificate();
			certificateValidityList = candidates.getCertificateValidityList();
			if (certificateValidityList.size() == 0) {

				// The public key can also be extracted from the signature.
				final KeyInfo extractedKeyInfo = santuarioSignature.getKeyInfo();
				final PublicKey publicKey;
				if (extractedKeyInfo == null || (publicKey = extractedKeyInfo.getPublicKey()) == null) {

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
	 * This method returns a {@code List} of {@code SigningCertificateValidity} base on the provided {@code providedSigningCertificateToken}. The field {@code
	 * candidatesForSigningCertificate} is instantiated.
	 *
	 * @param extractedPublicKey provided public key: {@code PublicKey}
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
	 * This method retrieves the potential countersignatures embedded in the XAdES signature document.
	 * From ETSI TS 101 903 v1.4.2:
	 * <p/>
	 * 7.2.4.1 Countersignature identifier in Type attribute of ds:Reference
	 * <p/>
	 * A XAdES signature containing a ds:Reference element whose Type attribute has value "http://uri.etsi.org/01903#CountersignedSignature"
	 * will indicate that is is, in fact, a countersignature of the signature referenced by this element.
	 * <p/>
	 * 7.2.4.2 Enveloped countersignatures: the CounterSignature element
	 * <p/>
	 * The CounterSignature is an unsigned property that qualifies the signature. A XAdES signature MAY have more
	 * than one CounterSignature properties. As indicated by its name, it contains one countersignature of the qualified
	 * signature.
	 *
	 * @return a list containing the countersignatures embedded in the XAdES signature document
	 */
	@Override
	public List<AdvancedSignature> getCounterSignatures() {

		// see ETSI TS 101 903 V1.4.2 (2010-12) pp. 38/39/40
		final NodeList counterSignatures = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_COUNTER_SIGNATURE);
		if (counterSignatures == null) {
			return null;
		}
		final List<AdvancedSignature> xadesList = new ArrayList<AdvancedSignature>();
		for (int ii = 0; ii < counterSignatures.getLength(); ii++) {

			final Element counterSignatureElement = (Element) counterSignatures.item(ii);
			final Element signatureElement = DSSXMLUtils.getElement(counterSignatureElement, xPathQueryHolder.XPATH__SIGNATURE);

			// Verify that the element is a proper signature by trying to build a XAdESSignature out of it
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
	 * <p/>
	 * From ETSI TS 101 903 V1.4.2:
	 * - The signature's ds:SignedInfo element MUST contain one ds:Reference element referencing the
	 * ds:Signature element of the embedding and countersigned XAdES signature
	 * - The content of the ds:DigestValue in the aforementioned ds:Reference element  of the countersignature
	 * MUST be the base-64 encoded digest of the complete (and canonicalized) ds:SignatureValue element (i.e.
	 * including the starting and closing tags) of the embedding and countersigned XAdES signature.
	 *
	 * @param xadesCounterSignature
	 * @return
	 */
	private boolean isCounterSignature(final XAdESSignature xadesCounterSignature) {

		final List<Element> signatureReferences = xadesCounterSignature.getSignatureReferences();
		//gets Element with Type="http://uri.etsi.org/01903#CountersignedSignature"
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

		Element signingCertEl = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_CERT_REFS);
		if (signingCertEl == null) {

			return null;
		}
		List<CertificateRef> certIds = new ArrayList<CertificateRef>();
		NodeList certIdnodes = DSSXMLUtils.getNodeList(signingCertEl, "./xades:Cert");
		for (int i = 0; i < certIdnodes.getLength(); i++) {

			Element certId = (Element) certIdnodes.item(i);
			Element issuerNameEl = DSSXMLUtils.getElement(certId, xPathQueryHolder.XPATH__X509_ISSUER_NAME);
			Element issuerSerialEl = DSSXMLUtils.getElement(certId, xPathQueryHolder.XPATH__X509_SERIAL_NUMBER);
			Element digestAlgorithmEl = DSSXMLUtils.getElement(certId, xPathQueryHolder.XPATH__CERT_DIGEST_DIGEST_METHOD);
			Element digestValueEl = DSSXMLUtils.getElement(certId, xPathQueryHolder.XPATH__CERT_DIGEST_DIGEST_VALUE);

			CertificateRef genericCertId = new CertificateRef();
			if (issuerNameEl != null && issuerSerialEl != null) {
				genericCertId.setIssuerName(issuerNameEl.getTextContent());
				genericCertId.setIssuerSerial(issuerSerialEl.getTextContent());
			}

			String xmlName = digestAlgorithmEl.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
			genericCertId.setDigestAlgorithm(DigestAlgorithm.forXML(xmlName).getName());

			genericCertId.setDigestValue(DSSUtils.base64Decode(digestValueEl.getTextContent()));
			certIds.add(genericCertId);
		}

		return certIds;

	}

	@Override
	public List<CRLRef> getCRLRefs() {

		final List<CRLRef> certIds = new ArrayList<CRLRef>();
		final Element signingCertEl = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_REVOCATION_CRL_REFS);
		if (signingCertEl != null) {

			final NodeList crlRefNodes = DSSXMLUtils.getNodeList(signingCertEl, xPathQueryHolder.XPATH__CRL_REF);
			for (int i = 0; i < crlRefNodes.getLength(); i++) {

				final Element certId = (Element) crlRefNodes.item(i);
				final Element digestAlgorithmEl = DSSXMLUtils.getElement(certId, xPathQueryHolder.XPATH__DAAV_DIGEST_METHOD);
				final Element digestValueEl = DSSXMLUtils.getElement(certId, xPathQueryHolder.XPATH__DAAV_DIGEST_VALUE);

				final String xmlName = digestAlgorithmEl.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
				final DigestAlgorithm digestAlgo = DigestAlgorithm.forXML(xmlName);

				final CRLRef ref = new CRLRef();
				ref.setDigestAlgorithm(digestAlgo);
				ref.setDigestValue(DSSUtils.base64Decode(digestValueEl.getTextContent()));
				certIds.add(ref);
			}
		}
		return certIds;
	}

	@Override
	public List<OCSPRef> getOCSPRefs() {

		final List<OCSPRef> certIds = new ArrayList<OCSPRef>();
		final Element signingCertEl = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_OCSP_REFS);
		if (signingCertEl != null) {

			final NodeList ocspRefNodes = DSSXMLUtils.getNodeList(signingCertEl, xPathQueryHolder.XPATH__OCSPREF);
			for (int i = 0; i < ocspRefNodes.getLength(); i++) {

				final Element certId = (Element) ocspRefNodes.item(i);
				final Element digestAlgorithmEl = DSSXMLUtils.getElement(certId, xPathQueryHolder.XPATH__DAAV_DIGEST_METHOD);
				final Element digestValueEl = DSSXMLUtils.getElement(certId, xPathQueryHolder.XPATH__DAAV_DIGEST_VALUE);

				if (digestAlgorithmEl == null || digestValueEl == null) {
					throw new DSSNotETSICompliantException(DSSNotETSICompliantException.MSG.XADES_DIGEST_ALG_AND_VALUE_ENCODING);
				}

				final String xmlName = digestAlgorithmEl.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
				final DigestAlgorithm digestAlgo = DigestAlgorithm.forXML(xmlName);

				final String digestValue = digestValueEl.getTextContent();
				final byte[] base64EncodedDigestValue = DSSUtils.base64Decode(digestValue);
				final OCSPRef ocspRef = new OCSPRef(digestAlgo, base64EncodedDigestValue, false);
				certIds.add(ocspRef);
			}
		}
		return certIds;
	}

	@Override
	public byte[] getSignatureTimestampData(final TimestampToken timestampToken) {

		final String canonicalizationMethod = getCanonicalizationMethod(timestampToken);
		final Node signatureValue = getSignatureValue();
		final byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, signatureValue);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Signature timestamp: canonicalization method  --> {}", canonicalizationMethod);
			LOG.trace("                   : canonicalized string     --> {}", new String(canonicalizedValue));
		}
		return canonicalizedValue;
	}

	private String getCanonicalizationMethod(final TimestampToken timestampToken) {

		String canonicalizationMethod;
		if (timestampToken != null) {

			canonicalizationMethod = timestampToken.getCanonicalizationMethod();
		} else {

			canonicalizationMethod = DEFAULT_TIMESTAMP_CREATION_CANONICALIZATION_METHOD;
		}
		return canonicalizationMethod;
	}

	@Override
	public byte[] getTimestampX1Data(final TimestampToken timestampToken) {

		final String canonicalizationMethod = getCanonicalizationMethod(timestampToken);
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try {

			getSignatureValue();
			final Element signatureValue = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_VALUE);
			byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, signatureValue);
			buffer.write(canonicalizedValue);

			final NodeList signatureTimeStampNode = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_TIMESTAMP);
			if (signatureTimeStampNode != null) {

				for (int ii = 0; ii < signatureTimeStampNode.getLength(); ii++) {

					final Node item = signatureTimeStampNode.item(ii);
					canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, item);
					buffer.write(canonicalizedValue);
				}
			}

			final Node completeCertificateRefsNode = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS);
			if (completeCertificateRefsNode != null) {

				canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, completeCertificateRefsNode);
				buffer.write(canonicalizedValue);
			}
			final Node completeRevocationRefsNode = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS);
			if (completeRevocationRefsNode != null) {

				canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, completeRevocationRefsNode);
				buffer.write(canonicalizedValue);
			}
			if (LOG.isTraceEnabled()) {
				LOG.trace("X1Timestamp (SigAndRefsTimeStamp) canonicalised string:\n" + buffer.toString());
			}
			final byte[] bytes = buffer.toByteArray();
			return bytes;
		} catch (IOException e) {

			throw new DSSException("Error when computing the SigAndRefsTimeStamp (X1Timestamp)", e);
		}
	}

	@Override
	public byte[] getTimestampX2Data(final TimestampToken timestampToken) {

		final String canonicalizationMethod = getCanonicalizationMethod(timestampToken);
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try {

			final Node completeCertificateRefsNode = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS);
			if (completeCertificateRefsNode != null) {

				final byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, completeCertificateRefsNode);
				buffer.write(canonicalizedValue);
			}
			final Node completeRevocationRefsNode = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS);
			if (completeRevocationRefsNode != null) {

				final byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, completeRevocationRefsNode);
				buffer.write(canonicalizedValue);
			}
			if (LOG.isTraceEnabled()) {
				LOG.trace("TimestampX2Data (RefsOnlyTimeStamp) canonicalised string:\n" + buffer.toString());
			}
			final byte[] bytes = buffer.toByteArray();
			return bytes;
		} catch (IOException e) {

			throw new DSSException("Error when computing the RefsOnlyTimeStamp (TimestampX2D)", e);
		}
	}

	/**
	 * Creates the hash sent to the TSA (messageImprint) computed on the XAdES-X-L or -A form of the electronic signature and the signed data objects<br>
	 *
	 * @param timestampToken null when adding a new archive timestamp
	 * @return
	 */
	@Override
	public byte[] getArchiveTimestampData(final TimestampToken timestampToken) {

		if (LOG.isTraceEnabled()) {
			LOG.trace("--->Get archive timestamp data:" + (timestampToken == null ? "--> CREATION" : "--> VALIDATION"));
		}
		final String canonicalizationMethod = getCanonicalizationMethod(timestampToken);
		/**
		 * 8.2.1 Not distributed case<br>
		 *
		 * When xadesv141:ArchiveTimeStamp and all the unsigned properties covered by its time-stamp certificateToken have the same
		 * parent, this property uses the Implicit mechanism for all the time-stamped data objects. The input to the
		 * computation of the digest value MUST be built as follows:
		 */
		try {

			/**
			 * 1) Initialize the final octet stream as an empty octet stream.
			 */
			final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

			/**
			 * 2) Take all the ds:Reference elements in their order of appearance within ds:SignedInfo referencing whatever
			 * the signer wants to sign including the SignedProperties element. Process each one as indicated below:<br>
			 * - Process the retrieved ds:Reference element according to the reference processing model of XMLDSIG.<br>
			 * - If the result is a XML node set, canonicalize it. If ds:Canonicalization is present, the algorithm
			 * indicated by this element is used. If not, the standard canonicalization method specified by XMLDSIG is
			 * used.<br>
			 * - Concatenate the resulting octets to the final octet stream.
			 */

			/**
			 * The references are already calculated {@see #checkSignatureIntegrity()}
			 */
			for (final Reference reference : references) {

				try {

					final byte[] bytes = reference.getReferencedBytes();
					DSSUtils.write(bytes, buffer);
				} catch (XMLSignatureException e) {
					throw new DSSException(e);
				}
			}
			/**
			 * 3) Take the following XMLDSIG elements in the order they are listed below, canonicalize each one and
			 * concatenate each resulting octet stream to the final octet stream:<br>
			 * - The ds:SignedInfo element.<br>
			 * - The ds:SignatureValue element.<br>
			 * - The ds:KeyInfo element, if present.
			 */
			byte[] canonicalizedValue;

			final Element signedInfo = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNED_INFO);
			canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, signedInfo);
			buffer.write(canonicalizedValue);

			final Element signatureValue = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_VALUE);
			canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, signatureValue);
			buffer.write(canonicalizedValue);

			final Element keyInfo = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_KEY_INFO);
			canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, keyInfo);
			buffer.write(canonicalizedValue);

			/**
			 * 4) Take the unsigned signature properties that appear before the current xadesv141:ArchiveTimeStamp in the
			 * order they appear within the xades:UnsignedSignatureProperties, canonicalize each one and concatenate each
			 * resulting octet stream to the final octet stream. While concatenating the following rules apply:
			 */

			// System.out.println("///### -------------------------------------> ");
			// DSSXMLUtils.printDocument(signatureElement.getOwnerDocument(), System.out);
			// System.out.println("<------------------------------------- ");

			final Element unsignedSignaturePropertiesNode = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
			if (unsignedSignaturePropertiesNode == null) {
				throw new DSSNullReturnedException(xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
			}
			// The archive timestamp need to be identified to know if it must be taken into account or not.
			int archiveTimeStampCount = 0;

			final NodeList unsignedProperties = unsignedSignaturePropertiesNode.getChildNodes();
			for (int ii = 0; ii < unsignedProperties.getLength(); ii++) {

				Node node = unsignedProperties.item(ii);
				final String localName = node.getLocalName();
				// This can happened when there is a blank line between tags.
				if (localName == null) {
					continue;
				}
				canonicalizedValue = null;
				// System.out.println("###: " + localName);
				// In the SD-DSS implementation when validating the signature the framework will not add missing data. To do so the signature must be extended.
				// if (localName.equals("CertificateValues")) {

				/**
				 * - The xades:CertificateValues property MUST be added if it is not already present and the ds:KeyInfo
				 * element does not contain the full set of certificates used to validate the electronic signature.
				 */

				// } else if (localName.equals("RevocationValues")) {

				/**
				 * - The xades:RevocationValues property MUST be added if it is not already present and the ds:KeyInfo
				 * element does not contain the revocation information that has to be shipped with the electronic
				 * signature
				 */

				// } else if (localName.equals("AttrAuthoritiesCertValues")) {

				/**
				 * - The xades:AttrAuthoritiesCertValues property MUST be added if not already present and the following
				 * conditions are true: there exist an attribute certificate in the signature AND a number of
				 * certificates that have been used in its validation do not appear in CertificateValues. Its content
				 * will satisfy with the rules specified in clause 7.6.3.
				 */

				// } else if (localName.equals("AttributeRevocationValues")) {

				/**
				 * - The xades:AttributeRevocationValues property MUST be added if not already present and there the
				 * following conditions are true: there exist an attribute certificate AND some revocation data that have
				 * been used in its validation do not appear in RevocationValues. Its content will satisfy with the rules
				 * specified in clause 7.6.4.
				 */

				// } else
				if (XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP.equals(localName) || XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP_V2.equals(localName)) {

					if (timestampToken != null && timestampToken.getDSSId() <= archiveTimeStampCount) {

						break;
					}
					archiveTimeStampCount++;
				} else if ("TimeStampValidationData".equals(localName)) {

					/**
					 * ETSI TS 101 903 V1.4.2 (2010-12)
					 * 8.1 The new XAdESv141:TimeStampValidationData element
					 * ../..
					 * This element is specified to serve as an optional container for validation data required for carrying a full verification of
					 * time-stamp tokens embedded within any of the different time-stamp containers defined in the present document.
					 * ../..
					 * 8.1.1 Use of URI attribute
					 * ../..
					 * a new xadesv141:TimeStampValidationData element SHALL be created containing the missing
					 validation data information and it SHALL be added as a child of UnsignedSignatureProperties elements
					 immediately after the respective time-stamp certificateToken container element.
					 */

					/**
					 * This is the work around for the name space problem: The issue was reported on: https://issues.apache.org/jira/browse/SANTUARIO-139 and considered as close.
					 * But for me (Bob) it still does not work!
					 */
					if (timestampToken == null) { // Creation of the timestamp

						final byte[] bytesToCanonicalize = DSSXMLUtils.serializeNode(node);
						canonicalizedValue = DSSXMLUtils.canonicalize(canonicalizationMethod, bytesToCanonicalize);
					}
				}

				if (canonicalizedValue == null) {
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
			 * Canonicalize each one and concatenate each resulting octet stream to the final octet stream. If
			 * ds:Canonicalization is present, the algorithm indicated by this element is used. If not, the standard
			 * canonicalization method specified by XMLDSIG is used.
			 */
			boolean xades141 = true;
			if (timestampToken != null && ArchiveTimestampType.XAdES.equals(timestampToken.getArchiveTimestampType())) {

				xades141 = false;
			}
			if (xades141) {

				NodeList objects = getObjects();
				for (int ii = 0; ii < objects.getLength(); ii++) {

					Node node = objects.item(ii);
					Node qualifyingProperties = DSSXMLUtils.getElement(node, xPathQueryHolder.XPATH__QUALIFYING_PROPERTIES);
					if (qualifyingProperties != null) {

						continue;
					}
					canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, node);
					buffer.write(canonicalizedValue);
				}
			}
			if (LOG.isTraceEnabled()) {
				LOG.trace("ArchiveTimestamp canonicalised string:\n" + buffer.toString());
			}
			final byte[] bytes = buffer.toByteArray();
			return bytes;
		} catch (IOException e) {
			throw new DSSException("Error when computing the archive data", e);
		}
	}

	@Override
	public String getId() {

		if (signatureId == null) {

			Node idElement = DSSXMLUtils.getNode(signatureElement, "./@Id");
			if (idElement == null) {
				idElement = DSSXMLUtils.getNode(signatureElement, "./@id");
				if (idElement == null) {
					idElement = DSSXMLUtils.getNode(signatureElement, "./@ID");
				}
			}
			if (idElement != null) {

				signatureId = idElement.getTextContent();
			} else {

				final CertificateToken certificateToken = getSigningCertificateToken();
				final int dssId = (certificateToken == null ? 0 : certificateToken.getDSSId());
				signatureId = DSSUtils.getDeterministicId(getSigningTime(), dssId);
			}
		}
		return signatureId;
	}

	@Override
	public List<TimestampReference> getTimestampedReferences() {

		final List<TimestampReference> references = new ArrayList<TimestampReference>();
		final NodeList certDigestList = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CERT_DIGEST);
		for (int jj = 0; jj < certDigestList.getLength(); jj++) {

			final Element certDigestElement = (Element) certDigestList.item(jj);
			final TimestampReference certificateReference = createCertificateTimestampReference(certDigestElement);
			references.add(certificateReference);
		}

		final Node completeCertificateRefsNode = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS);
		if (completeCertificateRefsNode != null) {

			final NodeList nodes = DSSXMLUtils.getNodeList(completeCertificateRefsNode, xPathQueryHolder.XPATH__COMPLETE_CERTIFICATE_REFS__CERT_DIGEST);
			for (int ii = 0; ii < nodes.getLength(); ii++) {

				final Element certDigestElement = (Element) nodes.item(ii);
				final TimestampReference certificateReference = createCertificateTimestampReference(certDigestElement);
				references.add(certificateReference);
			}
		}
		final Node completeRevocationRefsNode = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS);
		if (completeRevocationRefsNode != null) {

			final NodeList nodes = DSSXMLUtils.getNodeList(completeRevocationRefsNode, "./*/*/xades:DigestAlgAndValue");
			for (int ii = 0; ii < nodes.getLength(); ii++) {

				final Element element = (Element) nodes.item(ii);
				String digestAlgorithm = DSSXMLUtils.getNode(element, xPathQueryHolder.XPATH__DIGEST_METHOD_ALGORITHM).getTextContent();
				digestAlgorithm = DigestAlgorithm.forXML(digestAlgorithm).getName();
				final String digestValue = DSSXMLUtils.getElement(element, xPathQueryHolder.XPATH__DIGEST_VALUE).getTextContent();
				final TimestampReference revocationReference = new TimestampReference();
				revocationReference.setCategory(TimestampReferenceCategory.REVOCATION);
				revocationReference.setDigestAlgorithm(digestAlgorithm);
				revocationReference.setDigestValue(digestValue);
				references.add(revocationReference);
			}
		}
		return references;
	}

	/**
	 * Retrieves the name of each node found under the unsignedSignatureProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getUnsignedSignatureProperties() {

		final List<String> childrenNames = DSSXMLUtils.getChildrenNames(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
		return childrenNames;
	}

	public List<String> getSignedSignatureProperties() {

		final List<String> childrenNames = DSSXMLUtils.getChildrenNames(signatureElement, xPathQueryHolder.XPATH_SIGNED_SIGNATURE_PROPERTIES);
		return childrenNames;
	}

	public List<String> getSignedProperties() {

		final List<String> childrenNames = DSSXMLUtils.getChildrenNames(signatureElement, xPathQueryHolder.XPATH_SIGNED_PROPERTIES);
		return childrenNames;
	}

	public List<String> getUnsignedProperties() {

		final List<String> childrenNames = DSSXMLUtils.getChildrenNames(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_PROPERTIES);
		return childrenNames;
	}

	public List<String> getSignedDataObjectProperties() {

		final List<String> childrenNames = DSSXMLUtils.getChildrenNames(signatureElement, xPathQueryHolder.XPATH_SIGNED_DATA_OBJECT_PROPERTIES);
		return childrenNames;
	}

	/**
	 * @param element
	 * @return
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	private TimestampReference createCertificateTimestampReference(final Element element) throws DSSException {

		final String digestAlgorithm = DSSXMLUtils.getNode(element, xPathQueryHolder.XPATH__DIGEST_METHOD_ALGORITHM).getTextContent();
		final DigestAlgorithm digestAlgorithmObj = DigestAlgorithm.forXML(digestAlgorithm);
		if (!usedCertificatesDigestAlgorithms.contains(digestAlgorithmObj)) {

			usedCertificatesDigestAlgorithms.add(digestAlgorithmObj);
		}
		final Element digestValueElement = DSSXMLUtils.getElement(element, xPathQueryHolder.XPATH__DIGEST_VALUE);
		final String digestValue = (digestValueElement == null) ? "" : digestValueElement.getTextContent();
		final TimestampReference reference = new TimestampReference();
		reference.setCategory(TimestampReferenceCategory.CERTIFICATE);
		reference.setDigestAlgorithm(digestAlgorithmObj.getName());
		reference.setDigestValue(digestValue);
		return reference;
	}

	@Override
	public Set<DigestAlgorithm> getUsedCertificatesDigestAlgorithms() {

		return usedCertificatesDigestAlgorithms;
	}

	@Override
	public boolean isDataForSignatureLevelPresent(final SignatureLevel signatureLevel) {

		boolean dataForLevelPresent = true;
		switch (signatureLevel) {
			case XML_NOT_ETSI:
				break;
			case XAdES_BASELINE_LTA:
			case XAdES_A:
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
			case XAdES_XL:
				dataForLevelPresent &= hasXLProfile();
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
	public String validateStructure() {

		final String string = DSSXMLUtils.xmlToString(signatureElement);
		StringReader stringReader = new StringReader(string);
		final String validated = DSSXMLUtils.validateAgainstXSD(new StreamSource(stringReader));
		return  validated;
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
		final NodeList nodeList = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/*");
		boolean found = false;
		for (int ii = 0; ii < nodeList.getLength(); ii++) {

			final Element unsignedSignatureElement = (Element) nodeList.item(ii);
			final int hashCode = mostRecentTimestamp.getHashCode();
			final int nodeHashCode = unsignedSignatureElement.hashCode();
			if (nodeHashCode == hashCode) {

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
	 * // TODO (11/09/2014): to be deleted, eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature#getReferences() to be used
	 *
	 * @return
	 */
	public List<Element> getSignatureReferences() {

		final NodeList list = DSSXMLUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_REFERENCE);
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

		final NodeList list = DSSXMLUtils.getNodeList(signatureElement, XPathQueryHolder.XPATH_OBJECT);
		final List<Element> references = new ArrayList<Element>(list.getLength());
		for (int ii = 0; ii < list.getLength(); ii++) {

			final Node node = list.item(ii);
			final Element element = (Element) node;
			if (DSSXMLUtils.getElement(element, xPathQueryHolder.XPATH__QUALIFYING_PROPERTIES_SIGNED_PROPERTIES) != null) {
				// ignore signed properties
				continue;
			}
			references.add(element);
		}
		return references;
	}

	public void addXPathQueryHolder(XPathQueryHolder xPathQueryHolder) {
		xPathQueryHolders.add(xPathQueryHolder);
	}

	public Element getUnsignedSignaturePropertiesDom() {

		final Element unsignedSignaturePropertiesDom = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
		return unsignedSignaturePropertiesDom;
	}

	public Element getUnsignedPropertiesDom() {

		final Element unsignedPropertiesDom = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_PROPERTIES);
		return unsignedPropertiesDom;
	}

	public Element getQualifyingPropertiesDom() {

		final Element qualifyingPropertiesDom = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_QUALIFYING_PROPERTIES);
		return qualifyingPropertiesDom;
	}
}