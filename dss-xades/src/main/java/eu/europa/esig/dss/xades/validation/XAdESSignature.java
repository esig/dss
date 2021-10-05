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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommitmentTypeIndication;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.SignatureDigestReference;
import eu.europa.esig.dss.validation.SignatureIdentifierBuilder;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.SignerRole;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.SantuarioInitializer;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;
import eu.europa.esig.dss.xades.definition.XAdESPaths;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xades.reference.XAdESReferenceValidation;
import eu.europa.esig.dss.xades.validation.timestamp.XAdESTimestampSource;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.transform.dom.DOMSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Parse an XAdES signature structure. Note that for each signature to be validated a new instance of this object must
 * be created.
 *
 */
public class XAdESSignature extends DefaultAdvancedSignature {
	
	private static final long serialVersionUID = -2639858392612722185L;

	private static final Logger LOG = LoggerFactory.getLogger(XAdESSignature.class);
	
	/**
	 * The default canonicalization method used in {@link SignatureDigestReference} computation
	 */
	private static final String DEFAULT_CANONICALIZATION_METHOD = CanonicalizationMethod.EXCLUSIVE;

	/**
	 * This variable contains the list of {@code XAdESPaths} adapted to the specific
	 * signature schema.
	 */
	private final List<XAdESPaths> xadesPathsHolders;

	/** The current signature element */
	private final Element signatureElement;

	/** The XMLDSIG namespace */
	private DSSNamespace xmldSigNamespace;

	/** The current signature xades namespace */
	private DSSNamespace xadesNamespace;

	/** The XAdES XPaths to use */
	private XAdESPaths xadesPaths;

	/** Defines if the XSW protection shall be disabled (false by default) */
	private boolean disableXSWProtection = false;

	/** Cached Apache Santuario Signature */
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

		XAdESNamespaces.registerNamespaces();

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
		this(signatureElement, Arrays.asList(new XAdES132Paths()));
	}

	/**
	 * The default constructor for XAdESSignature.
	 *
	 * @param signatureElement
	 *                          the signature DOM element
	 * @param xadesPathsHolders
	 *                          List of {@code XAdESPaths} to use when handling
	 *                          signature
	 */
	public XAdESSignature(final Element signatureElement, final List<XAdESPaths> xadesPathsHolders) {
		Objects.requireNonNull(signatureElement, "Signature Element cannot be null");
		this.signatureElement = signatureElement;
		this.xadesPathsHolders = xadesPathsHolders;
		initialiseSettings();
	}

	/**
	 * NOT RECOMMENDED : This parameter allows to disable protection against XML
	 * Signature wrapping attacks (XSW). It disables the research by XPath
	 * expression for defined Type attributes.
	 * 
	 * @param disableXSWProtection
	 *                             true to disable the protection
	 */
	public void setDisableXSWProtection(boolean disableXSWProtection) {
		this.disableXSWProtection = disableXSWProtection;
	}

	/**
	 * This method is called when creating a new instance of the {@code XAdESSignature} with unknown schema.
	 */
	private void initialiseSettings() {
		recursiveNamespaceBrowser(signatureElement);

		if (xadesPaths == null) {
			LOG.warn("There is no suitable XAdESPaths / XAdESNamespace to manage the signature. The default ones will be used.");
			xadesPaths = new XAdES132Paths();
			xadesNamespace = XAdESNamespaces.XADES_132;
		}
	}

	/**
	 * This method sets the namespace which will determinate the {@code XAdESPaths} to use. The content of the
	 * Transform element is ignored.
	 *
	 * @param element {@link Element}
	 */
	public void recursiveNamespaceBrowser(final Element element) {
		for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {
			final Node node = element.getChildNodes().item(ii);
			if (node.getNodeType() == Node.ELEMENT_NODE) {
				final String prefix = node.getPrefix();
				final Element childElement = (Element) node;
				final String namespaceURI = childElement.getNamespaceURI();
				final String localName = childElement.getLocalName();
				if (XMLDSigElement.TRANSFORM.isSameTagName(localName) && XMLDSigElement.TRANSFORM.getURI().equals(namespaceURI)) {
					xmldSigNamespace = new DSSNamespace(namespaceURI, prefix);
					continue;
				} else if (XAdES132Element.QUALIFYING_PROPERTIES.isSameTagName(localName)) {
					setXAdESPathAndNamespace(prefix, namespaceURI);
					return;
				}
				recursiveNamespaceBrowser(childElement);
			}
		}
	}

	private void setXAdESPathAndNamespace(final String prefix, final String namespaceURI) {
		for (final XAdESPaths currentXAdESPaths : xadesPathsHolders) {
			if (currentXAdESPaths.getNamespace().isSameUri(namespaceURI)) {
				this.xadesPaths = currentXAdESPaths;
				this.xadesNamespace = new DSSNamespace(namespaceURI, prefix);
			}
		}
	}

	/**
	 * Returns a list of used {@code XAdESPaths}
	 *
	 * @return a list of {@code XAdESPaths}
	 */
	public List<XAdESPaths> getXAdESPathsHolders() {
		return xadesPathsHolders;
	}

	/**
	 * Gets the current {@code XAdESPaths}
	 *
	 * @return {@link XAdESPaths}
	 */
	public XAdESPaths getXAdESPaths() {
		return xadesPaths;
	}

	/**
	 * Returns the XMLDSIG namespace
	 *
	 * @return {@link DSSNamespace}
	 */
	public DSSNamespace getXmldSigNamespace() {
		return xmldSigNamespace;
	}

	/**
	 * Returns the XAdES namespace
	 *
	 * @return {@link DSSNamespace}
	 */
	public DSSNamespace getXadesNamespace() {
		return xadesNamespace;
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
		final String xmlName = DomUtils.getElement(signatureElement, XMLDSigPaths.SIGNATURE_METHOD_PATH)
				.getAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName());
		return SignatureAlgorithm.forXML(xmlName, null);
	}

	@Override
	public SignatureCertificateSource getCertificateSource() {
		if (offlineCertificateSource == null) {
			offlineCertificateSource = new XAdESCertificateSource(signatureElement, xadesPaths);
		}
		return offlineCertificateSource;
	}

	@Override
	public OfflineCRLSource getCRLSource() {
		if (signatureCRLSource == null) {
			signatureCRLSource = new XAdESCRLSource(signatureElement, xadesPaths);
		}
		return signatureCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {
		if (signatureOCSPSource == null) {
			signatureOCSPSource = new XAdESOCSPSource(signatureElement, xadesPaths);
		}
		return signatureOCSPSource;
	}
	
	@Override
	public XAdESTimestampSource getTimestampSource() {
		if (signatureTimestampSource == null) {
			signatureTimestampSource = new XAdESTimestampSource(this, signatureElement, xadesPaths);
		}
		return (XAdESTimestampSource) signatureTimestampSource;
	}

	@Override
	public Date getSigningTime() {

		final Element signingTimeEl = DomUtils.getElement(signatureElement, xadesPaths.getSigningTimePath());
		if (signingTimeEl == null) {
			return null;
		}
		final String text = signingTimeEl.getTextContent();
		return DomUtils.getDate(text);
	}

	@Override
	public XAdESSignaturePolicy getSignaturePolicy() {
		return (XAdESSignaturePolicy) super.getSignaturePolicy();
	}

	@Override
	protected XAdESSignaturePolicy buildSignaturePolicy() {
		XAdESSignaturePolicy xadesSignaturePolicy = null;

		final Element policyIdentifier = DomUtils.getElement(signatureElement, xadesPaths.getSignaturePolicyIdentifierPath());
		if (policyIdentifier != null) {
			// There is a policy
			final Element policyId = DomUtils.getElement(policyIdentifier, xadesPaths.getCurrentSignaturePolicyId());
			if (policyId != null) {
				// Explicit policy
				String policyUrlString = null;
				String policyIdString = policyId.getTextContent();
				policyIdString = DSSUtils.getObjectIdentifier(policyIdString);
				if (!DSSUtils.isUrnOid(policyIdString)) {
					policyUrlString = policyIdString;
				}

				xadesSignaturePolicy = new XAdESSignaturePolicy(policyIdString);

				final Digest digest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(policyIdentifier, xadesPaths.getCurrentSignaturePolicyDigestAlgAndValue()));
				xadesSignaturePolicy.setDigest(digest);

				final Element policyUrl = DomUtils.getElement(policyIdentifier, xadesPaths.getCurrentSignaturePolicySPURI());
				if (policyUrl != null) {
					policyUrlString = policyUrl.getTextContent();
					policyUrlString = Utils.trim(policyUrlString);
				}
				xadesSignaturePolicy.setUri(policyUrlString);

				final Element spUserNotice = DomUtils.getElement(policyIdentifier, xadesPaths.getCurrentSignaturePolicySPUserNotice());
				if (spUserNotice != null) {
					xadesSignaturePolicy.setUserNotice(buildSPUserNotice(spUserNotice));
				}

				String currentSignaturePolicySPDocSpecificationPath = xadesPaths.getCurrentSignaturePolicySPDocSpecification();
				if (Utils.isStringNotEmpty(currentSignaturePolicySPDocSpecificationPath)) {
					final Element spDocSpecification = DomUtils.getElement(policyIdentifier, currentSignaturePolicySPDocSpecificationPath);
					if (spDocSpecification != null) {
						xadesSignaturePolicy.setDocSpecification(buildSpDocSpecification(spDocSpecification));
					}
				}

				final Element policyDescription = DomUtils.getElement(policyIdentifier, xadesPaths.getCurrentSignaturePolicyDescription());
				if (policyDescription != null && Utils.isStringNotEmpty(policyDescription.getTextContent())) {
					xadesSignaturePolicy.setDescription(policyDescription.getTextContent());
				}

				final Element docRefsNode = DomUtils.getElement(policyIdentifier, xadesPaths.getCurrentSignaturePolicyDocumentationReferences());
				if (docRefsNode != null) {
					xadesSignaturePolicy.setDocumentationReferences(getDocumentationReferences(docRefsNode));
				}

				final Element transformsNode = DomUtils.getElement(policyIdentifier, xadesPaths.getCurrentSignaturePolicyTransforms());
				if (transformsNode != null) {
					xadesSignaturePolicy.setTransforms(transformsNode);
					xadesSignaturePolicy.setHashAsInTechnicalSpecification(isHashComputationAsInPolicySpecification(transformsNode));
				}

			} else {
				// Implicit policy
				final Element signaturePolicyImplied = DomUtils.getElement(policyIdentifier, xadesPaths.getCurrentSignaturePolicyImplied());
				if (signaturePolicyImplied != null) {
					xadesSignaturePolicy = new XAdESSignaturePolicy();
				}
				
			}
		}
		return xadesSignaturePolicy;
	}

	private UserNotice buildSPUserNotice(Element spUserNoticeElement) {
		try {
			final UserNotice userNotice = new UserNotice();

			final Element organization = DomUtils.getElement(spUserNoticeElement, xadesPaths.getCurrentSPUserNoticeNoticeRefOrganization());
			if (organization != null) {
				userNotice.setOrganization(organization.getTextContent());
			}
			final Element noticeNumbers = DomUtils.getElement(spUserNoticeElement, xadesPaths.getCurrentSPUserNoticeNoticeRefNoticeNumbers());
			if (noticeNumbers != null && noticeNumbers.hasChildNodes()) {
				final List<Integer> noticeNumbersList = new ArrayList<>();
				NodeList childNodes = noticeNumbers.getChildNodes();
				for (int ii = 0; ii < childNodes.getLength(); ii++) {
					Node child = childNodes.item(ii);
					if (Node.ELEMENT_NODE == child.getNodeType() && XAdES132Element.INT.isSameTagName(child.getLocalName())) {
						noticeNumbersList.add(Integer.valueOf(child.getTextContent()));
					}
				}
				userNotice.setNoticeNumbers(noticeNumbersList.stream().mapToInt(i -> i).toArray());
			}
			final Element explicitText = DomUtils.getElement(spUserNoticeElement, xadesPaths.getCurrentSPUserNoticeExplicitText());
			if (explicitText != null) {
				userNotice.setExplicitText(explicitText.getTextContent());
			}

			return userNotice;

		} catch (Exception e) {
			LOG.error("Unable to build SPUserNotice qualifier. Reason : {}", e.getMessage(), e);
			return null;
		}
	}

	private boolean isHashComputationAsInPolicySpecification(Element transforms) {
		if (transforms != null && transforms.hasChildNodes()) {
			NodeList transformList = DomUtils.getNodeList(transforms, XMLDSigPaths.TRANSFORM_PATH);
			if (transformList.getLength() == 1) {
				Node transform = transformList.item(0);
				String algorithm = DomUtils.getValue(transform, "@Algorithm");
				if (DSSXMLUtils.SP_DOC_DIGEST_AS_IN_SPECIFICATION_ALGORITHM_URI.equals(algorithm)) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {

		NodeList nodeList = DomUtils.getNodeList(signatureElement, xadesPaths.getSignatureProductionPlacePath());
		if ((nodeList.getLength() == 0) || (nodeList.item(0) == null)) {
			String signatureProductionPlaceV2Path = xadesPaths.getSignatureProductionPlaceV2Path();
			if (signatureProductionPlaceV2Path != null) {
				nodeList = DomUtils.getNodeList(signatureElement, signatureProductionPlaceV2Path);
			}
		}
		if ((nodeList.getLength() == 0) || (nodeList.item(0) == null)) {
			return null;
		}
		final SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
		final NodeList list = nodeList.item(0).getChildNodes();
		for (int ii = 0; ii < list.getLength(); ii++) {

			final Node item = list.item(ii);
			final String name = item.getLocalName();
			final String nodeValue = item.getTextContent();
			if (XAdES132Element.CITY.isSameTagName(name)) {
				signatureProductionPlace.setCity(nodeValue);
			} else if (XAdES132Element.STATE_OR_PROVINCE.isSameTagName(name)) {
				signatureProductionPlace.setStateOrProvince(nodeValue);
			} else if (XAdES132Element.POSTAL_CODE.isSameTagName(name)) {
				signatureProductionPlace.setPostalCode(nodeValue);
			} else if (XAdES132Element.COUNTRY_NAME.isSameTagName(name)) {
				signatureProductionPlace.setCountryName(nodeValue);
			} else if (XAdES132Element.STREET_ADDRESS.isSameTagName(name)) {
				signatureProductionPlace.setStreetAddress(nodeValue);
			}
		}
		return signatureProductionPlace;
	}

	@Override
	public SignaturePolicyStore getSignaturePolicyStore() {
		String signaturePolicyStorePath = xadesPaths.getSignaturePolicyStorePath();
		if (Utils.isStringNotEmpty(signaturePolicyStorePath)) {
			NodeList nodeList = DomUtils.getNodeList(signatureElement, signaturePolicyStorePath);
			if (nodeList.getLength() > 0) {
				SignaturePolicyStore sps = new SignaturePolicyStore();
				
				Element signaturePolicyStoreElement = (Element) nodeList.item(0);
				String id = signaturePolicyStoreElement.getAttribute(XMLDSigAttribute.ID.getAttributeName());
				if (Utils.isStringNotEmpty(id)) {
					sps.setId(id);
				}

				SpDocSpecification spDocSpec = null;
				String currentSPDocSpecificationPath = xadesPaths.getCurrentSPDocSpecification();
				if (Utils.isStringNotEmpty(currentSPDocSpecificationPath)) {
					Element spDocSpecificationElement = DomUtils.getElement(signaturePolicyStoreElement, currentSPDocSpecificationPath);
					if (spDocSpecificationElement != null) {
						spDocSpec = buildSpDocSpecification(spDocSpecificationElement);
					}
				}
				sps.setSpDocSpecification(spDocSpec);

				String currentSignaturePolicyDocumentPath = xadesPaths.getCurrentSignaturePolicyDocument();
				if (Utils.isStringNotEmpty(currentSignaturePolicyDocumentPath)) {
					String spDocB64 = DomUtils.getValue(signaturePolicyStoreElement, currentSignaturePolicyDocumentPath);
					if (Utils.isStringNotEmpty(spDocB64) && Utils.isBase64Encoded(spDocB64)) {
						sps.setSignaturePolicyContent(new InMemoryDocument(Utils.fromBase64(spDocB64)));
					}
				}
				return sps;
			}
		}
		return null;
	}

	private SpDocSpecification buildSpDocSpecification(Element spDocSpecificationElement) {
		SpDocSpecification spDocSpec = new SpDocSpecification();

		Element identifierElement = DomUtils.getElement(spDocSpecificationElement, xadesPaths.getCurrentIdentifier());
		if (identifierElement != null) {
			String spDocSpecId = identifierElement.getTextContent();
			spDocSpec.setId(DSSUtils.getObjectIdentifier(spDocSpecId));

			String qualifierString = identifierElement.getAttribute(XAdES132Attribute.QUALIFIER.getAttributeName());
			if (Utils.isStringNotBlank(qualifierString)) {
				spDocSpec.setQualifier(ObjectIdentifierQualifier.fromValue(qualifierString));
			}
		}

		String description = DomUtils.getValue(spDocSpecificationElement, xadesPaths.getCurrentDescription());
		spDocSpec.setDescription(description);

		String currentDocumentationReferenceElementsPath = xadesPaths.getCurrentDocumentationReferenceElements();
		if (Utils.isStringNotEmpty(currentDocumentationReferenceElementsPath)) {
			String[] documentationReferences = null;
			NodeList documentReferenceList = DomUtils.getNodeList(spDocSpecificationElement, currentDocumentationReferenceElementsPath);
			if (documentReferenceList != null && documentReferenceList.getLength() > 0) {
				documentationReferences = new String[documentReferenceList.getLength()];
				for (int i = 0; i < documentReferenceList.getLength(); i++) {
					documentationReferences[i] = documentReferenceList.item(i).getTextContent();
				}
			}
			spDocSpec.setDocumentationReferences(documentationReferences);
		}

		return spDocSpec;
	}

	@Override
	public List<SignerRole> getSignedAssertions() {
		List<SignerRole> result = new ArrayList<>();
		String signedAssertionPath = xadesPaths.getSignedAssertionPath();
		if (signedAssertionPath != null) {
			NodeList nodeList = DomUtils.getNodeList(signatureElement, signedAssertionPath);
			for (int ii = 0; ii < nodeList.getLength(); ii++) {
				result.add(new SignerRole(DomUtils.xmlToString(nodeList.item(ii).getFirstChild()), EndorsementType.SIGNED));
			}
		}
		return result;
	}

	@Override
	public List<SignerRole> getClaimedSignerRoles() {
		NodeList nodeList = DomUtils.getNodeList(signatureElement, xadesPaths.getClaimedRolePath());
		if (nodeList.getLength() == 0) {
			String claimedRoleV2Path = xadesPaths.getClaimedRoleV2Path();
			if (claimedRoleV2Path != null) {
				nodeList = DomUtils.getNodeList(signatureElement, claimedRoleV2Path);
				if (nodeList.getLength() == 0) {
					return Collections.emptyList();
				}
			}
		}
		List<SignerRole> claimedRoles = new ArrayList<>();
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
		NodeList nodeList = DomUtils.getNodeList(signatureElement, xadesPaths.getCertifiedRolePath());
		if (nodeList.getLength() == 0) {
			String certifiedRoleV2Path = xadesPaths.getCertifiedRoleV2Path();
			if (certifiedRoleV2Path != null) {
				nodeList = DomUtils.getNodeList(signatureElement, certifiedRoleV2Path);
				if (nodeList.getLength() == 0) {
					return Collections.emptyList();
				}
			}
		}
		final List<SignerRole> certifiedRoles = new ArrayList<>();
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
		final NodeList allContentTypes = DomUtils.getNodeList(signatureElement, xadesPaths.getDataObjectFormatObjectIdentifier());
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
		final NodeList allMimeTypes = DomUtils.getNodeList(signatureElement, xadesPaths.getDataObjectFormatMimeType());
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
	
	/**
	 * Returns a base64 SignatureValue
	 * 
	 * @return base64 {@link String}
	 */
	public String getSignatureValueBase64() {
		Element signatureValueElement = DomUtils.getElement(signatureElement, XMLDSigPaths.SIGNATURE_VALUE_PATH);
		if (signatureValueElement != null) {
			return signatureValueElement.getTextContent();
		}
		return null;
	}

	@Override
	public byte[] getSignatureValue() {
		String signatureValueBase64 = getSignatureValueBase64();
		if (signatureValueBase64 != null) {
			return Utils.fromBase64(signatureValueBase64);
		}
		return null;
	}

	/**
	 * Returns Id of the ds:SignatureValue element
	 *
	 * @return {@link String} Id
	 */
	public String getSignatureValueId() {
		return DomUtils.getValue(signatureElement, XMLDSigPaths.SIGNATURE_VALUE_ID_PATH);
	}

	/**
	 * This method returns the list of ds:Object elements for the current signature element.
	 *
	 * @return {@link NodeList}
	 */
	public NodeList getObjects() {
		return DomUtils.getNodeList(signatureElement, XMLDSigPaths.OBJECT_PATH);
	}

	/**
	 * Gets xades:CompleteCertificateRefs or xades141:CompleteCertificateRefsV2 element
	 *
	 * @return {@link Element}
	 */
	public Element getCompleteCertificateRefs() {
		Element element = null;
		String completeCertificateRefsPath = xadesPaths.getCompleteCertificateRefsPath();
		if (Utils.isStringNotEmpty(completeCertificateRefsPath)) {
			element = DomUtils.getElement(signatureElement, completeCertificateRefsPath);
		}
		String completeCertificateRefsV2Path = xadesPaths.getCompleteCertificateRefsV2Path();
		if (element == null && Utils.isStringNotEmpty(completeCertificateRefsV2Path)) {
			element = DomUtils.getElement(signatureElement, completeCertificateRefsV2Path);
		}
		return element;
	}

	/**
	 * Gets xades:CompleteRevocationRefs
	 *
	 * @return {@link Element}
	 */
	public Element getCompleteRevocationRefs() {
		return DomUtils.getElement(signatureElement, xadesPaths.getCompleteRevocationRefsPath());
	}

	/**
	 * Gets xades:SigAndRefsTimeStamp node list
	 *
	 * @return {@link NodeList}
	 */
	public NodeList getSigAndRefsTimeStamp() {
		NodeList nodeList = null;
		String sigAndRefsTimestampPath = xadesPaths.getSigAndRefsTimestampPath();
		if (Utils.isStringNotEmpty(sigAndRefsTimestampPath)) {
			nodeList = DomUtils.getNodeList(signatureElement, sigAndRefsTimestampPath);
		}
		String sigAndRefsTimestampV2Path = xadesPaths.getSigAndRefsTimestampV2Path();
		if ((nodeList == null || nodeList.getLength() == 0) && Utils.isStringNotEmpty(sigAndRefsTimestampV2Path)) {
			nodeList = DomUtils.getNodeList(signatureElement, sigAndRefsTimestampV2Path);
		}
		return nodeList;
	}

	/**
	 * Gets xades:RefsOnlyTimestamp node list
	 *
	 * @return {@link NodeList}
	 */
	public NodeList getRefsOnlyTimestampTimeStamp() {
		NodeList nodeList = null;
		String refsOnlyTimestampPath = xadesPaths.getRefsOnlyTimestampPath();
		if (Utils.isStringNotEmpty(refsOnlyTimestampPath)) {
			nodeList = DomUtils.getNodeList(signatureElement, refsOnlyTimestampPath);
		}
		String refsOnlyTimestampV2Path = xadesPaths.getRefsOnlyTimestampV2Path();
		if ((nodeList == null || nodeList.getLength() == 0) && Utils.isStringNotEmpty(refsOnlyTimestampV2Path)) {
			nodeList = DomUtils.getNodeList(signatureElement, refsOnlyTimestampV2Path);
		}
		return nodeList;
	}

	/**
	 * Gets xades:CertificateValues element
	 *
	 * @return {@link Element}
	 */
	public Element getCertificateValues() {
		return DomUtils.getElement(signatureElement, xadesPaths.getCertificateValuesPath());
	}

	/**
	 * Gets xades:RevocationValues element
	 *
	 * @return {@link Element}
	 */
	public Element getRevocationValues() {
		return DomUtils.getElement(signatureElement, xadesPaths.getRevocationValuesPath());
	}

	@Override
	public void addExternalTimestamp(TimestampToken timestamp) {
		throw new UnsupportedOperationException("The action is not supported for XAdES!");
	}

	@Override
	protected XAdESBaselineRequirementsChecker getBaselineRequirementsChecker() {
		return (XAdESBaselineRequirementsChecker) super.getBaselineRequirementsChecker();
	}

	@Override
	protected XAdESBaselineRequirementsChecker createBaselineRequirementsChecker() {
		return new XAdESBaselineRequirementsChecker(this, offlineCertificateVerifier);
	}

	/**
	 * Checks the presence of CompleteCertificateRefs and CompleteRevocationRefs segments in the signature, what is the
	 * proof -C profile existence
	 *
	 * @return true if C Profile is detected
	 */
	public boolean hasCProfile() {
		return getBaselineRequirementsChecker().hasExtendedCProfile();
	}

	/**
	 * Checks the presence of SigAndRefsTimeStamp segment in the signature, what is the proof -X profile existence
	 *
	 * @return true if the -X extension is present
	 */
	public boolean hasXProfile() {
		return getBaselineRequirementsChecker().hasExtendedXProfile();
	}

	/**
	 * Checks the presence of CertificateValues/RevocationValues segment in the signature, what is the proof -XL profile existence
	 *
	 * @return true if the -XL extension is present
	 */
	public boolean hasXLProfile() {
		return getBaselineRequirementsChecker().hasExtendedXLProfile();
	}

	/**
	 * Checks the presence of ArchiveTimeStamp element in the signature, what is the proof -A profile existence
	 *
	 * @return true if the -A extension is present
	 */
	public boolean hasAProfile() {
		return getBaselineRequirementsChecker().hasExtendedAProfile();
	}

	@Override
	public void checkSignatureIntegrity() {
		if (signatureCryptographicVerification != null) {
			return;
		}
		signatureCryptographicVerification = new SignatureCryptographicVerification();
		try {
			final XMLSignature currentSantuarioSignature = getSantuarioSignature();
			CandidatesForSigningCertificate candidatesForSigningCertificate = getCandidatesForSigningCertificate();
			
			SignatureIntegrityValidator signingCertificateValidator = new XAdESSignatureIntegrityValidator(currentSantuarioSignature);
			CertificateValidity certificateValidity = signingCertificateValidator.validate(candidatesForSigningCertificate);
			if (certificateValidity != null) {
				candidatesForSigningCertificate.setTheCertificateValidity(certificateValidity);
			}
			
			List<String> errorMessages = signingCertificateValidator.getErrorMessages();
			signatureCryptographicVerification.setErrorMessages(errorMessages);

			boolean allReferenceDataFound = true;
			boolean allReferenceDataIntact = true;
			List<ReferenceValidation> refValidations = getReferenceValidations();
			for (ReferenceValidation referenceValidation : refValidations) {
				allReferenceDataFound = allReferenceDataFound && referenceValidation.isFound();
				allReferenceDataIntact = allReferenceDataIntact && referenceValidation.isIntact();
			}

			signatureCryptographicVerification.setReferenceDataFound(allReferenceDataFound);
			signatureCryptographicVerification.setReferenceDataIntact(allReferenceDataIntact);
			signatureCryptographicVerification.setSignatureIntact(certificateValidity != null);
			
		} catch (Exception e) {
			LOG.error("checkSignatureIntegrity : {}", e.getMessage());
			LOG.debug("checkSignatureIntegrity : {}", e.getMessage(), e);
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
			referenceValidations = new ArrayList<>();

			final XMLSignature currentSantuarioSignature = getSantuarioSignature();
			boolean atLeastOneReferenceElementFound = false;
			
			List<Reference> santuarioReferences = getReferences();
			for (Reference reference : santuarioReferences) {
				XAdESReferenceValidation validation = new XAdESReferenceValidation(reference);
				validation.setType(DigestMatcherType.REFERENCE);

				referenceValidations.add(validation);

				boolean found = false;
				boolean intact = false;
				
				try {
					final Digest digest = DSSXMLUtils.getReferenceDigest(reference);
					validation.setDigest(digest);

					found = DSSXMLUtils.isAbleToDeReferenceContent(reference);

					final String uri = validation.getUri();
					boolean isDuplicated = DSSXMLUtils.isReferencedContentAmbiguous(
							signatureElement.getOwnerDocument(), uri);
					validation.setDuplicated(isDuplicated);
					
					boolean isElementReference = DomUtils.isElementReference(uri);
							
					if (isElementReference && DSSXMLUtils.isSignedProperties(reference, xadesPaths)) {
						validation.setType(DigestMatcherType.SIGNED_PROPERTIES);
						found = found && (disableXSWProtection || findSignedPropertiesById(uri));
						
					} else if (DomUtils.isXPointerQuery(uri)) {
						validation.setType(DigestMatcherType.XPOINTER);
						// found is checked in the reference validation
						
					} else if (DSSXMLUtils.isCounterSignature(reference, xadesPaths)) {
						validation.setType(DigestMatcherType.COUNTER_SIGNATURE);
						// found is checked in the reference validation
						XAdESSignature masterSignature = (XAdESSignature) getMasterSignature();
						if (masterSignature != null) {
							referenceValidations.add(getCounterSignatureReferenceValidation(reference, masterSignature));
						} else {
							LOG.warn("Master signature is not found! " +
									"Unable to verify counter signed SignatureValue for detached signatures.");
						}
						
					} else if (isElementReference && DSSXMLUtils.isKeyInfoReference(reference,
							currentSantuarioSignature.getElement())) {
						validation.setType(DigestMatcherType.KEY_INFO);
						found = true; // we check it in prior inside "isKeyInfoReference" method
						
					} else if (isElementReference && DSSXMLUtils.isSignaturePropertiesReference(reference,
							currentSantuarioSignature.getElement())) {
						validation.setType(DigestMatcherType.SIGNATURE_PROPERTIES);
						found = true; // Id is verified inside "isSignaturePropertiesReference" method
						
					} else if (isElementReference && reference.typeIsReferenceToObject()) {
						validation.setType(DigestMatcherType.OBJECT);
						found = found && (disableXSWProtection || findObjectById(uri));
						
					} else if (isElementReference && reference.typeIsReferenceToManifest()) {
						validation.setType(DigestMatcherType.MANIFEST);
						Element manifestElement = getManifestById(uri);
						found = found && (disableXSWProtection || (manifestElement != null));
						if (manifestElement != null) {
							validation.getDependentValidations().addAll(getManifestReferences(manifestElement));
						}
						
					}
					
					if (found && !isDuplicated) {
						intact = reference.verify();
					}
					
				} catch (Exception e) {
					LOG.warn("Unable to verify reference with Id [{}] : {}", reference.getId(), e.getMessage(), e);
				}
				
				if (DigestMatcherType.REFERENCE.equals(validation.getType()) || DigestMatcherType.OBJECT.equals(validation.getType()) ||
						DigestMatcherType.MANIFEST.equals(validation.getType()) || DigestMatcherType.XPOINTER.equals(validation.getType()) ||
						DigestMatcherType.COUNTER_SIGNATURE.equals(validation.getType())) {
					atLeastOneReferenceElementFound = true;
				}
					
				validation.setFound(found);
				validation.setIntact(intact);
				
			}

			// If at least one reference is not found, we add an empty
			// referenceValidation
			if (!atLeastOneReferenceElementFound) {
				referenceValidations.add(notFound(DigestMatcherType.REFERENCE));
			}
			
			if (referenceValidations.size() < santuarioReferences.size()) {
				LOG.warn("Not all references were validated!");
			}
			
		}
		return referenceValidations;
	}

	private ReferenceValidation getCounterSignatureReferenceValidation(Reference counterSignatureReference,
																	   XAdESSignature masterSignature) {
		ReferenceValidation referenceValidation = new ReferenceValidation();
		referenceValidation.setType(DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE);

		String masterSignatureValueBase64 = masterSignature.getSignatureValueBase64();
		if (Utils.isStringNotEmpty(masterSignatureValueBase64)) {
			referenceValidation.setFound(true);

			try {
				byte[] referencedBytes = counterSignatureReference.getContentsAfterTransformation().getBytes();
				Document document = DomUtils.buildDOM(referencedBytes);
				Element referencedElement = document.getDocumentElement();
				if (XMLDSigElement.SIGNATURE_VALUE.isSameTagName(referencedElement.getLocalName())) {
					String referencedSignatureValueBase64 = referencedElement.getTextContent();
					boolean intact = Utils.areStringsEqual(masterSignatureValueBase64, referencedSignatureValueBase64);
					if (!intact) {
						LOG.warn("The referenced counter signed value does not match " +
								"the master signature's ds:SignatureValue content!");
					}
					referenceValidation.setIntact(intact);

				} else {
					LOG.warn("The counter signature reference does not result to a ds:SignatureValue element!");
				}

			} catch (Exception e) {
				LOG.warn("Unable to verify the counter signed reference! Reason : {}", e.getMessage(), e);
			}

		} else {
			LOG.warn("Master signature's ds:SignatureValue element does not contain data!");
		}

		return referenceValidation;
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

	@Override
	public Digest getDataToBeSignedRepresentation() {
		DigestAlgorithm digestAlgorithm = getDigestAlgorithm();
		if (digestAlgorithm == null) {
			LOG.warn("DigestAlgorithm is not found! Unable to compute DTBSR.");
			return null;
		}
		final Element signedInfo = getSignedInfo();
		if (signedInfo == null) {
			LOG.warn("SignedInfo element is not found! Unable to compute DTBSR.");
			return null;
		}
		String canonicalizationMethod = DomUtils.getValue(signedInfo, XMLDSigPaths.CANONICALIZATION_ALGORITHM_PATH);
		if (Utils.isStringEmpty(canonicalizationMethod)) {
			LOG.warn("Canonicalization method is not present in SignedInfo element! Unable to compute DTBSR.");
			return null;
		}
		byte[] canonicalizedSignedInfo = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, signedInfo);
		return new Digest(digestAlgorithm, DSSUtils.digest(digestAlgorithm, canonicalizedSignedInfo));
	}

	/**
	 * Returns the ds:SignedInfo element
	 *
	 * @return {@link Element} ds:SignedInfo
	 */
	public Element getSignedInfo() {
		try {
			return DomUtils.getElement(signatureElement, XMLDSigPaths.SIGNED_INFO_PATH);
		} catch (DSSException e) {
			LOG.warn(String.format("Unable to extract ds:SignedInfo element! Reason : %s.", e.getMessage()), e);
			return null;
		}
	}
	
	/**
	 * Returns a list of all references contained in the given manifest
	 * @param manifestElement {@link Element} to get references from
	 * @return list of {@link ReferenceValidation} objects
	 */
	private List<ReferenceValidation> getManifestReferences(Element manifestElement) {
		ManifestValidator mv = new ManifestValidator(manifestElement, detachedContents);
		return mv.validate();
	}

	private boolean findSignedPropertiesById(String uri) {
		return getSignedPropertiesById(uri) != null;
	}

	private Node getSignedPropertiesById(String uri) {
		if (Utils.isStringNotBlank(uri)) {
			String signedPropertiesById = xadesPaths.getSignedPropertiesPath() + DomUtils.getXPathByIdAttribute(uri);
			return DomUtils.getNode(signatureElement, signedPropertiesById);
		}
		return null;
	}

	private boolean findObjectById(String uri) {
		return getObjectById(uri) != null;
	}

	/**
	 * Gets ds:Object by its Id
	 *
	 * @param id {@link String} object Id
	 * @return {@link Node}
	 */
	public Node getObjectById(String id) {
		if (Utils.isStringNotBlank(id)) {
			String objectById = XMLDSigPaths.OBJECT_PATH + DomUtils.getXPathByIdAttribute(id);
			return DomUtils.getNode(signatureElement, objectById);
		}
		return null;
	}

	/**
	 * Gets ds:Manifest by its Id
	 *
	 * @param id {@link String} manifest Id
	 * @return {@link Element} Manifest
	 */
	public Element getManifestById(String id) {
		if (Utils.isStringNotBlank(id)) {
			String manifestById = XMLDSigPaths.MANIFEST_PATH + DomUtils.getXPathByIdAttribute(id);
			return DomUtils.getElement(signatureElement, manifestById);
		}
		return null;
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

			// Secure validation disabled to support all signature algos
			santuarioSignature = new XMLSignature(signatureElement, "", false);
			if (Utils.isCollectionNotEmpty(detachedContents)) {
				initDetachedSignatureResolvers(detachedContents);
				initCounterSignatureResolver(detachedContents);
			}
			return santuarioSignature;
		} catch (XMLSecurityException e) {
			throw new DSSException("Unable to initialize santuario XMLSignature", e);
		}
	}

	private void initDetachedSignatureResolvers(List<DSSDocument> detachedContents) {
		Element signedInfo = getSignedInfo();
		if (signedInfo != null) {
			XMLSignature santuarioSignature = getSantuarioSignature();
			List<DigestAlgorithm> usedReferenceDigestAlgos = DSSXMLUtils.getReferenceDigestAlgos(signedInfo);
			for (DigestAlgorithm digestAlgorithm : usedReferenceDigestAlgos) {
				santuarioSignature.addResourceResolver(new DetachedSignatureResolver(detachedContents, digestAlgorithm));
			}
		}
	}
	
	/**
	 * Used for a counter signature extension only
	 */
	private void initCounterSignatureResolver(List<DSSDocument> detachedContents) {
		Element signedInfo = getSignedInfo();
		if (signedInfo != null) {
			XMLSignature santuarioSignature = getSantuarioSignature();
			List<String> types = DSSXMLUtils.getReferenceTypes(signedInfo);
			for (String type : types) {
				if (xadesPaths.getCounterSignatureUri().equals(type)) {
					for (DSSDocument document : detachedContents) {
						// only one SignatureValue document shall be provided
						if (isDetachedSignatureValueDocument(document)) {
							santuarioSignature.addResourceResolver(new CounterSignatureResolver(document));
							break;
						}
					}
				}
			}
		}
	}
	
	private boolean isDetachedSignatureValueDocument(DSSDocument detachedContents) {
		try {
			if (DomUtils.isDOM(detachedContents)) {
				Document document = DomUtils.buildDOM(detachedContents);
				if (document != null) {
					Node node = document.getChildNodes().item(0);
					return XMLDSigElement.SIGNATURE_VALUE.getTagName().equals(node.getLocalName());
				}
			}
		} catch (Exception e) {
			// continue
		}
		return false;
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
		if (counterSignatures != null) {
			return counterSignatures;
		}
		
		counterSignatures = new ArrayList<>();

		// see ETSI TS 101 903 V1.4.2 (2010-12) pp. 38/39/40
		final NodeList counterSignaturesElements = DomUtils.getNodeList(signatureElement,
				xadesPaths.getCounterSignaturePath());
		if (counterSignaturesElements != null && counterSignaturesElements.getLength() > 0) {
			for (int ii = 0; ii < counterSignaturesElements.getLength(); ii++) {
				XAdESSignature counterSignature = DSSXMLUtils.createCounterSignature(
						(Element) counterSignaturesElements.item(ii), this);
				if (counterSignature != null) {
					counterSignatures.add(counterSignature);
				}
			}
		}
		return counterSignatures;
	}
	
	@Override
	protected SignatureIdentifierBuilder getSignatureIdentifierBuilder() {
		return new XAdESSignatureIdentifierBuilder(this);
	}
	
	@Override
	public String getDAIdentifier() {
		if (daIdentifier == null) {
			daIdentifier = DSSXMLUtils.getIDIdentifier(signatureElement);
		}
		return daIdentifier;
	}

	/**
	 * Retrieves the name of each node found under the UnsignedSignatureProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getUnsignedSignatureProperties() {
		return DomUtils.getChildrenNames(signatureElement, xadesPaths.getUnsignedSignaturePropertiesPath());
	}

	/**
	 * Retrieves the name of each node found under the SignedSignatureProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getSignedSignatureProperties() {
		return DomUtils.getChildrenNames(signatureElement, xadesPaths.getSignedSignaturePropertiesPath());
	}

	/**
	 * Retrieves the name of each node found under the SignedProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getSignedProperties() {
		return DomUtils.getChildrenNames(signatureElement, xadesPaths.getSignedPropertiesPath());
	}

	/**
	 * Retrieves the name of each node found under the UnsignedProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getUnsignedProperties() {
		return DomUtils.getChildrenNames(signatureElement, xadesPaths.getUnsignedPropertiesPath());
	}

	/**
	 * Retrieves the name of each node found under the SignedDataObjectProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getSignedDataObjectProperties() {
		return DomUtils.getChildrenNames(signatureElement, xadesPaths.getSignedDataObjectPropertiesPath());
	}

	@Override
	public SignatureLevel getDataFoundUpToLevel() {
		if (!hasBProfile()) {
			return SignatureLevel.XML_NOT_ETSI;
		}
		if (!hasTProfile()) {
			return SignatureLevel.XAdES_BASELINE_B;
		}

		if (hasLTProfile()) {
			if (hasLTAProfile()) {
				return SignatureLevel.XAdES_BASELINE_LTA;
			}
			return SignatureLevel.XAdES_BASELINE_LT;
		} else if (hasCProfile()) {
			if (hasXLProfile()) {
				if (hasAProfile()) {
					return SignatureLevel.XAdES_A;
				}
				if (hasXProfile()) {
					return SignatureLevel.XAdES_XL;
				}
			}
			if (hasXProfile()) {
				return SignatureLevel.XAdES_X;
			}
			return SignatureLevel.XAdES_C;
		} else {
			return SignatureLevel.XAdES_BASELINE_T;
		}
	}

	@Override
	public List<String> validateStructure() {
		return DSSXMLUtils.validateAgainstXSD(xadesPaths.getXSDUtils(), new DOMSource(signatureElement));
	}

	/**
	 * This method returns the last timestamp validation data for an archive
	 * timestamp.
	 *
	 * @return {@link Element} xades141:TimestampValidationData
	 */
	public Element getLastTimestampValidationData() {
		final NodeList nodeList = DomUtils.getNodeList(signatureElement, xadesPaths.getUnsignedSignaturePropertiesPath() + "/*");
		if (nodeList.getLength() > 0) {
			final Element unsignedSignatureElement = (Element) nodeList.item(nodeList.getLength() - 1);
			final String nodeName = unsignedSignatureElement.getLocalName();
			if (XAdES141Element.TIMESTAMP_VALIDATION_DATA.isSameTagName(nodeName)) {
				return unsignedSignatureElement;
			}
		}
		return null;
	}

	@Override
	public List<CommitmentTypeIndication> getCommitmentTypeIndications() {
		List<CommitmentTypeIndication> result = null;
		NodeList nodeList = DomUtils.getNodeList(signatureElement, xadesPaths.getCommitmentTypeIndicationPath());
		if (nodeList != null && nodeList.getLength() > 0) {
			result = new ArrayList<>();
			for (int ii = 0; ii < nodeList.getLength(); ii++) {
				Node commitmentTypeIndicationNode = nodeList.item(ii);
				String uri = DomUtils.getValue(commitmentTypeIndicationNode, xadesPaths.getCurrentCommitmentIdentifierPath());
				if (uri == null) {
					LOG.warn("The Identifier for a CommitmentTypeIndication is not defined! The CommitmentType is skipped.");
					continue;
				}
				CommitmentTypeIndication commitmentTypeIndication = new CommitmentTypeIndication(uri);
				
				Element descriptionNode = DomUtils.getElement(commitmentTypeIndicationNode, xadesPaths.getCurrentCommitmentDescriptionPath());
				if (descriptionNode != null) {
					commitmentTypeIndication.setDescription(descriptionNode.getTextContent());
				}
				Element docRefsNode = DomUtils.getElement(commitmentTypeIndicationNode, xadesPaths.getCurrentCommitmentDocumentationReferencesPath());
				if (docRefsNode != null) {
					commitmentTypeIndication.setDocumentReferences(getDocumentationReferences(docRefsNode));
				}
				result.add(commitmentTypeIndication);
			}
		}
		return result;
	}
	
	private List<String> getDocumentationReferences(Element docRefsNode) {
		NodeList docRefsChildNodes = DomUtils.getNodeList(docRefsNode, xadesPaths.getCurrentDocumentationReference());
		if (docRefsChildNodes.getLength() > 0) {
			List<String> docRefs = new ArrayList<>();
			for (int jj = 0; jj < docRefsChildNodes.getLength(); jj++) {
				Node docRefNode = docRefsChildNodes.item(jj);
				docRefs.add(docRefNode.getTextContent());
			}
			return docRefs;
		}
		return null;
	}

	/**
	 * Gets a list of found references
	 *
	 * @return a list of {@link Reference}s
	 */
	public List<Reference> getReferences() {
		if (references == null) {
			XMLSignature santuarioSignature = getSantuarioSignature();
			SignedInfo signedInfo = santuarioSignature.getSignedInfo();
            references = DSSXMLUtils.extractReferences(signedInfo);
		}
		return references;
	}

	/**
	 * Gets a list of found signature ds:Object elements
	 *
	 * @return a list of {@link Element}s
	 */
	public List<Element> getSignatureObjects() {
		final NodeList list = DomUtils.getNodeList(signatureElement, XMLDSigPaths.OBJECT_PATH);
		final List<Element> references = new ArrayList<>(list.getLength());
		for (int ii = 0; ii < list.getLength(); ii++) {
			final Node node = list.item(ii);
			final Element element = (Element) node;
			if (DomUtils.getElement(element, xadesPaths.getSignedPropertiesPath()) != null) {
				// ignore signed properties
				continue;
			}
			references.add(element);
		}
		return references;
	}

	/**
	 * This method allows to register a new {@code XAdESPaths}.
	 *
	 * @param xadesPaths
	 *                   {@code XAdESPaths} to register
	 */
	public void registerXAdESPaths(final XAdESPaths xadesPaths) {
		xadesPathsHolders.add(xadesPaths);
	}

}
