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

import java.io.StringReader;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.transform.stream.StreamSource;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.ReferenceNotInitializedException;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.identifier.TokenIdentifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CandidatesForSigningCertificate;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.CertificateValidity;
import eu.europa.esig.dss.validation.CommitmentType;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.IssuerSerialInfo;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.SignatureCRLSource;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.SignatureDigestReference;
import eu.europa.esig.dss.validation.SignatureIdentifier;
import eu.europa.esig.dss.validation.SignatureOCSPSource;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.SignerRole;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.SantuarioInitializer;
import eu.europa.esig.dss.xades.XAdESUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import eu.europa.esig.dss.xades.reference.XAdESReferenceValidation;

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
	 * The default canonicalization method used in {@link SignatureDigestReference} computation
	 */
	protected static final String DEFAULT_CANONICALIZATION_METHOD = CanonicalizationMethod.EXCLUSIVE;

	/**
	 * This variable contains the list of {@code XPathQueryHolder} adapted to the specific signature schema.
	 */
	private final List<XPathQueryHolder> xPathQueryHolders;

	/**
	 * This variable contains the XPathQueryHolder adapted to the signature schema.
	 */
	protected XPathQueryHolder xPathQueryHolder;

	private final Element signatureElement;
	
	private transient XMLSignature santuarioSignature;
	
	/**
	 * A signature identifier provided by a Driving Application.
	 */
	private String daIdentifier;

	/**
	 * This variable contains all references found within the signature. They are extracted when the method
	 * {@code checkSignatureIntegrity} is called.
	 */
	private transient List<Reference> references;

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
	public SignatureCertificateSource getCertificateSource() {
		if (offlineCertificateSource == null) {
			offlineCertificateSource = new XAdESCertificateSource(signatureElement, xPathQueryHolder, certPool);
		}
		return offlineCertificateSource;
	}

	/**
	 * This method resets the source of certificates. It must be called when any certificate is added to the KeyInfo or
	 * CertificateValues.
	 */
	public void resetCertificateSource() {
		offlineCertificateSource = null;
	}

	@Override
	public SignatureCRLSource getCRLSource() {
		if (signatureCRLSource == null) {
			signatureCRLSource = new XAdESCRLSource(signatureElement, xPathQueryHolder);
		}
		return signatureCRLSource;
	}

	@Override
	public SignatureOCSPSource getOCSPSource() {
		if (signatureOCSPSource == null) {
			signatureOCSPSource = new XAdESOCSPSource(signatureElement, xPathQueryHolder);
		}
		return signatureOCSPSource;
	}

	/**
	 * This method resets the sources of the revocation data. It must be called when -LT level is created.
	 */
	public void resetRevocationSources() {
		signatureCRLSource = null;
		signatureOCSPSource = null;
	}
	
	@Override
	public XAdESTimestampSource getTimestampSource() {
		if (signatureTimestampSource == null) {
			signatureTimestampSource = new XAdESTimestampSource(this, signatureElement, xPathQueryHolder, certPool);
		}
		return (XAdESTimestampSource) signatureTimestampSource;
	}

	/**
	 * This method resets the timestamp source. It must be called when -LT level is created.
	 */
	public void resetTimestampSource() {
		signatureTimestampSource = null;
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
		final SignatureCertificateSource certSource = getCertificateSource();
		for (final CertificateToken certificateToken : certSource.getKeyInfoCertificates()) {
			final CertificateValidity certificateValidity = new CertificateValidity(certificateToken);
			candidatesForSigningCertificate.add(certificateValidity);
		}
		return candidatesForSigningCertificate;
	}

	@Override
	public void checkSigningCertificate() {

		final CandidatesForSigningCertificate candidates = getCandidatesForSigningCertificate();
		final List<CertificateRef> potentialSigningCertificates = getCertificateSource().getSigningCertificateValues();

		final List<CertificateValidity> certificateValidityList = candidates.getCertificateValidityList();
		for (final CertificateValidity certificateValidity : certificateValidityList) {
			certificateValidity.setAttributePresent(Utils.isCollectionNotEmpty(potentialSigningCertificates));

			final CertificateToken certificateToken = certificateValidity.getCertificateToken();
			
			if (Utils.isCollectionNotEmpty(potentialSigningCertificates)) {
				// must contain only one reference
				final CertificateRef signingCert = potentialSigningCertificates.get(0);

				Digest certDigest = signingCert.getCertDigest();
				if (certDigest != null) {
					certificateValidity.setDigestPresent(true);
					DigestAlgorithm digestAlgorithm = certDigest.getAlgorithm();
					byte[] expectedDigest = certDigest.getValue();
					byte[] currentDigest = certificateToken.getDigest(digestAlgorithm);
					boolean digestEqual = Arrays.equals(expectedDigest, currentDigest);
					certificateValidity.setDigestEqual(digestEqual);
				}

				IssuerSerialInfo issuerInfo = signingCert.getIssuerInfo();
				if (issuerInfo != null) {
					BigInteger serialNumber = issuerInfo.getSerialNumber();
					X500Principal issuerName = issuerInfo.getIssuerName();

					BigInteger certSerialNumber = certificateToken.getSerialNumber();
					X500Principal certIssuerName = certificateToken.getIssuerX500Principal();

					certificateValidity.setSerialNumberEqual(certSerialNumber.equals(serialNumber));

					final boolean issuerNameMatches = DSSUtils.x500PrincipalAreEquals(certIssuerName, issuerName);
					certificateValidity.setDistinguishedNameEqual(issuerNameMatches);
					if (!issuerNameMatches) {
						final String c14nCandidateIssuerName = certIssuerName.getName(X500Principal.CANONICAL);
						LOG.info("candidateIssuerName : {}", c14nCandidateIssuerName);
						final String c14nIssuerName = issuerName == null ? "" : issuerName.getName(X500Principal.CANONICAL);
						LOG.info("issuerName : {}", c14nIssuerName);
					}
				}

				// If the signing certificate is not set yet then it must be
				// done now. Actually if the signature is tempered then the
				// method checkSignatureIntegrity cannot set the signing
				// certificate.
				if (candidates.getTheCertificateValidity() == null) {
					candidates.setTheCertificateValidity(certificateValidity);
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
				final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(policyDigestMethodString);
				final Element policyDigestValue = DomUtils.getElement(policyIdentifier, xPathQueryHolder.XPATH__POLICY_DIGEST_VALUE);
				final byte[] digestValue = Utils.fromBase64(policyDigestValue.getTextContent().trim());
				signaturePolicy.setDigest(new Digest(digestAlgorithm, digestValue));
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
	public List<SignerRole> getClaimedSignerRoles() {
		NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CLAIMED_ROLE);
		if (nodeList.getLength() == 0) {
			nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_CLAIMED_ROLE_V2);
			if (nodeList.getLength() == 0) {
				return Collections.emptyList();
			}
		}
		List<SignerRole> claimedRoles = new ArrayList<SignerRole>();
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			claimedRoles.add(new SignerRole(nodeList.item(ii).getTextContent(), EndorsementType.CLAIMED));
		}
		return claimedRoles;
	}

	@Override
	public List<SignerRole> getCertifiedSignerRoles() {
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
				return Collections.emptyList();
			}
		}
		final List<SignerRole> certifiedRoles = new ArrayList<SignerRole>();
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			final Element certEl = (Element) nodeList.item(ii);
			final String textContent = certEl.getTextContent();
			certifiedRoles.add(new SignerRole(textContent, EndorsementType.CERTIFIED));
		}
		return certifiedRoles;
	}

	@Override
	public String getContentType() {
		String contentType = null;
		final NodeList allContentTypes = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ALL_DATA_OBJECT_FORMAT_OBJECT_IDENTIFIER);
		if (allContentTypes != null && allContentTypes.getLength() > 0) {
			for (int i = 0; i < allContentTypes.getLength(); i++) {
				Node node = allContentTypes.item(i);
				if (node instanceof Element) {
					Element element = (Element) node;
					contentType = element.getTextContent();
					// TODO returns the first one
					break;
				}
			}
		}
		return contentType;
	}

	@Override
	public String getMimeType() {
		String mimeType = null;
		final NodeList allMimeTypes = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_ALL_DATA_OBJECT_FORMAT_MIMETYPE);
		if (allMimeTypes != null && allMimeTypes.getLength() > 0) {
			for (int i = 0; i < allMimeTypes.getLength(); i++) {
				Node node = allMimeTypes.item(i);
				if (node instanceof Element) {
					Element element = (Element) node;
					mimeType = element.getTextContent();
					// TODO returns the first one
					break;
				}
			}
		}
		return mimeType;
	}

	@Override
	public String getContentIdentifier() {
		return null;
	}

	@Override
	public String getContentHints() {
		return null;
	}

	@Override
	public byte[] getSignatureValue() {
		Element signatureValueElement = DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_VALUE);
		if (signatureValueElement != null) {
			return Utils.fromBase64(signatureValueElement.getTextContent());
		}
		return null;
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
	
	private void extractReferences() {
		references = new ArrayList<Reference>();
		final XMLSignature santuarioSignature = getSantuarioSignature();
		final SignedInfo signedInfo = santuarioSignature.getSignedInfo();
		final int numberOfReferences = signedInfo.getLength();
		for (int ii = 0; ii < numberOfReferences; ii++) {
			try {
				final Reference reference = signedInfo.item(ii);
				references.add(reference);
			} catch (XMLSecurityException e) {
				LOG.warn("Unable to retrieve reference #{} : {}", ii, e.getMessage());
			}
		}
	}

	@Override
	public List<ReferenceValidation> getReferenceValidations() {
		if (referenceValidations == null) {
			referenceValidations = new ArrayList<ReferenceValidation>();

			final XMLSignature santuarioSignature = getSantuarioSignature();
			boolean atLeastOneReferenceElementFound = false;
			
			List<Reference> references = getReferences();
			for (Reference reference : references) {
				XAdESReferenceValidation validation = new XAdESReferenceValidation(reference);
				validation.setType(DigestMatcherType.REFERENCE);
				boolean found = false;
				boolean intact = false;
				
				try {
					
					final Digest digest = new Digest();
					digest.setValue(reference.getDigestValue());
					digest.setAlgorithm(
							DigestAlgorithm.forXML(reference.getMessageDigestAlgorithm().getAlgorithmURI()));
					validation.setDigest(digest);

					try {
						found = reference.getContentsBeforeTransformation() != null;
					} catch (ReferenceNotInitializedException e) {
						// continue, exception will be catched later
					}
					
					final String uri = validation.getUri();
					
					boolean noDuplicateIdFound = XMLUtils.protectAgainstWrappingAttack(santuarioSignature.getDocument(), DomUtils.getId(uri));
					boolean isElementReference = DomUtils.isElementReference(uri);
							
					if (isElementReference && XAdESUtils.isSignedProperties(reference, xPathQueryHolder)) {
						validation.setType(DigestMatcherType.SIGNED_PROPERTIES);
						found = found && (noDuplicateIdFound && findSignedPropertiesById(uri));
						
					} else if (DomUtils.isXPointerQuery(uri)) {
						validation.setType(DigestMatcherType.XPOINTER);
						found = found && noDuplicateIdFound;
						
					} else if (isElementReference && XAdESUtils.isKeyInfoReference(reference, santuarioSignature.getElement(), xPathQueryHolder)) {
						validation.setType(DigestMatcherType.KEY_INFO);
						found = true; // we check it in prior inside "isKeyInfoReference" method
						
					} else if (isElementReference && reference.typeIsReferenceToObject()) {
						validation.setType(DigestMatcherType.OBJECT);
						found = found && (noDuplicateIdFound && findObjectById(uri));
						
					} else if (isElementReference && reference.typeIsReferenceToManifest()) {
						validation.setType(DigestMatcherType.MANIFEST);
						Node manifestNode = getManifestById(uri);
						found = found && (noDuplicateIdFound && (manifestNode != null));
						if (manifestNode != null) {
							validation.getDependentValidations().addAll(getManifestReferences(manifestNode));
						}
						
					} else {
						found = found && noDuplicateIdFound;
						
					}
					
					if (found) {
						intact = reference.verify();
					}
					
				} catch (Exception e) {
					LOG.warn("Unable to verify reference with Id [{}] : {}", reference.getId(), e.getMessage(), e);
					
				}
				
				if (DigestMatcherType.REFERENCE.equals(validation.getType()) || DigestMatcherType.OBJECT.equals(validation.getType()) ||
						DigestMatcherType.MANIFEST.equals(validation.getType()) || DigestMatcherType.XPOINTER.equals(validation.getType())) {
					atLeastOneReferenceElementFound = true;
				}
					
				validation.setFound(found);
				validation.setIntact(intact);
				referenceValidations.add(validation);
				
			}

			// If at least one reference is not found, we add an empty
			// referenceValidation
			if (!atLeastOneReferenceElementFound) {
				referenceValidations.add(notFound(DigestMatcherType.REFERENCE));
			}
			
			if (referenceValidations.size() < references.size()) {
				LOG.warn("Not all references were validated!");
			}
			
		}
		return referenceValidations;
	}

	/**
	 * TS 119 442 - V1.1.1 - Electronic Signatures and Infrastructures (ESI), ch. 5.1.4.2.1.3 XML component:
	 * 
	 * In case of XAdES signatures, the input of the digest value computation shall be the result of applying the
	 * canonicalization algorithm identified within the CanonicalizationMethod child element's value to the
	 * corresponding ds:Signature element and its contents. The canonicalization shall be computed keeping this
	 * ds:Signature element as a descendant of the XML root element, without detaching it.
	 */
	@Override
	public SignatureDigestReference getSignatureDigestReference(DigestAlgorithm digestAlgorithm) {
		byte[] signatureElementBytes = DSSXMLUtils.canonicalizeSubtree(DEFAULT_CANONICALIZATION_METHOD, signatureElement);
		byte[] digestValue = DSSUtils.digest(digestAlgorithm, signatureElementBytes);
		return new SignatureDigestReference(DEFAULT_CANONICALIZATION_METHOD, new Digest(digestAlgorithm, digestValue));
	}
	
	/**
	 * Returns a list of all references contained in the given manifest
	 * @param manifestNode {@link Node} to get references from
	 * @return list of {@link ReferenceValidation} objects
	 */
	public List<ReferenceValidation> getManifestReferences(Node manifestNode) {
		ManifestValidator mv = new ManifestValidator(signatureElement, manifestNode, detachedContents, xPathQueryHolder);
		return mv.validate();
	}

	private boolean findSignedPropertiesById(String uri) {
		return getSignedPropertiesById(uri) != null;
	}

	private Node getSignedPropertiesById(String uri) {
		String signedPropertiesById = xPathQueryHolder.XPATH_SIGNED_PROPERTIES + DomUtils.getXPathByIdAttribute(uri);
		return DomUtils.getNode(signatureElement, signedPropertiesById);
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
		if (santuarioSignature != null) {
			return santuarioSignature;
		}
		try {
			final Document document = signatureElement.getOwnerDocument();
			final Element rootElement = document.getDocumentElement();

			DSSXMLUtils.setIDIdentifier(rootElement);
			DSSXMLUtils.recursiveIdBrowse(rootElement);

			santuarioSignature = new XMLSignature(signatureElement, "");
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
		final List<Reference> references = xadesCounterSignature.getReferences();
		for (final Reference reference : references) {
			if (XAdESUtils.isCounerSignature(reference, xPathQueryHolder)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public List<CertificateRef> getCertificateRefs() {
		return getCertificateSource().getCompleteCertificateRefs();
	}
	
	@Override
	protected SignatureIdentifier buildSignatureIdentifier() {
		final CertificateToken certificateToken = getSigningCertificateToken();
		final TokenIdentifier identifier = certificateToken == null ? null : certificateToken.getDSSId();
		return SignatureIdentifier.buildSignatureIdentifier(getSigningTime(), identifier, getDAIdentifier());
	}
	
	@Override
	public String getDAIdentifier() {
		if (daIdentifier == null) {
			daIdentifier = DSSXMLUtils.getIDIdentifier(signatureElement);
		}
		return daIdentifier;
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
		final NodeList nodeList = DomUtils.getNodeList(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/*");
		if (nodeList.getLength() > 0) {
			final Element unsignedSignatureElement = (Element) nodeList.item(nodeList.getLength() - 1);
			final String nodeName = unsignedSignatureElement.getLocalName();
			if ("TimeStampValidationData".equals(nodeName)) {
				return unsignedSignatureElement;
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

	public List<Reference> getReferences() {
		if (references == null) {
			extractReferences();
		}
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

}
