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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.signature.CommitmentTypeIndication;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.model.signature.SignatureDigestReference;
import eu.europa.esig.dss.model.signature.SignatureProductionPlace;
import eu.europa.esig.dss.model.signature.SignerRole;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.signature.DefaultAdvancedSignature;
import eu.europa.esig.dss.spi.signature.identifier.SignatureIdentifierBuilder;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.EnforcedResolverFragment;
import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xades.reference.XAdESReferenceValidation;
import eu.europa.esig.dss.xades.validation.scope.XAdESSignatureScopeFinder;
import eu.europa.esig.dss.xades.validation.timestamp.XAdESTimestampSource;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigPath;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.SantuarioInitializer;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverXPointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
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
	private final List<XAdESPath> xadesPathHolders;

	/** The current signature element */
	private final Element signatureElement;

	/** The XMLDSIG namespace */
	private DSSNamespace xmldSigNamespace;

	/** The current signature xades namespace */
	private DSSNamespace xadesNamespace;

	/** The XAdES XPath to use */
	private XAdESPath xadesPath;

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

		DSSXMLUtils.registerXAdESNamespaces();

		//
		// Set the default JCE algorithms
		//
		JCEMapper.setProviderId(DSSSecurityProvider.getSecurityProviderName());
		JCEMapper.registerDefaultAlgorithms();

		/*
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

		initDefaultResolvers();

	}

	/**
	 * Customized
	 * org.apache.xml.security.utils.resolver.ResourceResolver.registerDefaultResolvers()
	 * <p>
	 * Ignore references which point to a file (file://) or external http urls
	 * Enforce ResolverFragment against XPath injections
	 */
	private static void initDefaultResolvers() {
		ResourceResolver.register(new EnforcedResolverFragment(), false);
		ResourceResolver.register(new ResolverXPointer(), false);
	}

	/**
	 * This constructor is used when creating the signature. The default {@code XPathQueryHolder} is set.
	 *
	 * @param signatureElement
	 *            the signature DOM element
	 */
	public XAdESSignature(final Element signatureElement) {
		this(signatureElement, Collections.singletonList(new XAdES132Path()));
	}

	/**
	 * The default constructor for XAdESSignature.
	 *
	 * @param signatureElement
	 *                          the signature DOM element
	 * @param xadesPathHolders
	 *                          List of {@code XAdESPaths} to use when handling
	 *                          signature
	 */
	public XAdESSignature(final Element signatureElement, final List<XAdESPath> xadesPathHolders) {
		Objects.requireNonNull(signatureElement, "Signature Element cannot be null");
		this.signatureElement = signatureElement;
		this.xadesPathHolders = xadesPathHolders;
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

		if (xadesPath == null) {
			LOG.warn("There is no suitable XAdESPaths / XAdESNamespace to manage the signature. The default ones will be used.");
			xadesPath = new XAdES132Path();
			xadesNamespace = XAdESNamespace.XADES_132;
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
		for (final XAdESPath currentXAdESPaths : xadesPathHolders) {
			if (currentXAdESPaths.getNamespace().isSameUri(namespaceURI)) {
				this.xadesPath = currentXAdESPaths;
				this.xadesNamespace = new DSSNamespace(namespaceURI, prefix);
			}
		}
	}

	/**
	 * Returns a list of used {@code XAdESPaths}
	 *
	 * @return a list of {@code XAdESPaths}
	 */
	public List<XAdESPath> getXAdESPathsHolders() {
		return xadesPathHolders;
	}

	/**
	 * Gets the current {@code XAdESPaths}
	 *
	 * @return {@link XAdESPath}
	 */
	public XAdESPath getXAdESPaths() {
		return xadesPath;
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
	public SignatureAlgorithm getSignatureAlgorithm() {
		final String xmlName = DomUtils.getElement(signatureElement, XMLDSigPath.SIGNATURE_METHOD_PATH)
				.getAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName());
		SignatureAlgorithm signatureAlgorithm =  SignatureAlgorithm.forXML(xmlName, null);
		if (signatureAlgorithm == null) {
			LOG.warn("SignatureAlgorithm '{}' is not supported!", xmlName);
		}
		return signatureAlgorithm;
	}

	@Override
	public SignatureCertificateSource getCertificateSource() {
		if (offlineCertificateSource == null) {
			offlineCertificateSource = new XAdESCertificateSource(signatureElement, xadesPath);
		}
		return offlineCertificateSource;
	}

	@Override
	public OfflineCRLSource getCRLSource() {
		if (signatureCRLSource == null) {
			signatureCRLSource = new XAdESCRLSource(signatureElement, xadesPath);
		}
		return signatureCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {
		if (signatureOCSPSource == null) {
			signatureOCSPSource = new XAdESOCSPSource(signatureElement, xadesPath);
		}
		return signatureOCSPSource;
	}
	
	@Override
	public XAdESTimestampSource getTimestampSource() {
		if (signatureTimestampSource == null) {
			signatureTimestampSource = new XAdESTimestampSource(this);
		}
		return (XAdESTimestampSource) signatureTimestampSource;
	}

	@Override
	public Date getSigningTime() {

		final Element signingTimeEl = DomUtils.getElement(signatureElement, xadesPath.getSigningTimePath());
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

		final Element policyIdentifier = DomUtils.getElement(signatureElement, xadesPath.getSignaturePolicyIdentifierPath());
		if (policyIdentifier != null) {
			// There is a policy
			final Element policyId = DomUtils.getElement(policyIdentifier, xadesPath.getCurrentSignaturePolicyId());
			if (policyId != null) {
				// Explicit policy
				String policyUrlString = null;

				ObjectIdentifierQualifier qualifier = null;
				String qualifierString = policyId.getAttribute(XAdES132Attribute.QUALIFIER.getAttributeName());
				if (Utils.isStringNotBlank(qualifierString)) {
					qualifier = ObjectIdentifierQualifier.fromValue(qualifierString);
				}

				String policyIdString = policyId.getTextContent();
				policyIdString = DSSUtils.getObjectIdentifierValue(policyIdString, qualifier);
				if (Utils.isStringNotBlank(policyIdString) && !DSSUtils.isUrnOid(policyIdString) && !DSSUtils.isOidCode(policyIdString)) {
					policyUrlString = policyIdString;
				}

				xadesSignaturePolicy = new XAdESSignaturePolicy(policyIdString);

				final Digest digest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(policyIdentifier, xadesPath.getCurrentSignaturePolicyDigestAlgAndValue()));
				xadesSignaturePolicy.setDigest(digest);

				final Element policyUrl = DomUtils.getElement(policyIdentifier, xadesPath.getCurrentSignaturePolicySPURI());
				if (policyUrl != null) {
					policyUrlString = policyUrl.getTextContent();
					policyUrlString = DSSUtils.trimWhitespacesAndNewlines(policyUrlString);
				}
				xadesSignaturePolicy.setUri(policyUrlString);

				final Element spUserNotice = DomUtils.getElement(policyIdentifier, xadesPath.getCurrentSignaturePolicySPUserNotice());
				if (spUserNotice != null) {
					xadesSignaturePolicy.setUserNotice(buildSPUserNotice(spUserNotice));
				}

				String currentSignaturePolicySPDocSpecificationPath = xadesPath.getCurrentSignaturePolicySPDocSpecification();
				if (Utils.isStringNotEmpty(currentSignaturePolicySPDocSpecificationPath)) {
					final Element spDocSpecification = DomUtils.getElement(policyIdentifier, currentSignaturePolicySPDocSpecificationPath);
					if (spDocSpecification != null) {
						xadesSignaturePolicy.setDocSpecification(buildSpDocSpecification(spDocSpecification));
					}
				}

				final Element policyDescription = DomUtils.getElement(policyIdentifier, xadesPath.getCurrentSignaturePolicyDescription());
				if (policyDescription != null && Utils.isStringNotEmpty(policyDescription.getTextContent())) {
					xadesSignaturePolicy.setDescription(policyDescription.getTextContent());
				}

				final Element docRefsNode = DomUtils.getElement(policyIdentifier, xadesPath.getCurrentSignaturePolicyDocumentationReferences());
				if (docRefsNode != null) {
					xadesSignaturePolicy.setDocumentationReferences(getDocumentationReferences(docRefsNode));
				}

				final Element transformsNode = DomUtils.getElement(policyIdentifier, xadesPath.getCurrentSignaturePolicyTransforms());
				if (transformsNode != null) {
					xadesSignaturePolicy.setTransforms(transformsNode);
					xadesSignaturePolicy.setHashAsInTechnicalSpecification(isHashComputationAsInPolicySpecification(transformsNode));
				}

			} else {
				// Implicit policy
				final Element signaturePolicyImplied = DomUtils.getElement(policyIdentifier, xadesPath.getCurrentSignaturePolicyImplied());
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

			final Element organization = DomUtils.getElement(spUserNoticeElement, xadesPath.getCurrentSPUserNoticeNoticeRefOrganization());
			if (organization != null) {
				userNotice.setOrganization(organization.getTextContent());
			}
			final Element noticeNumbers = DomUtils.getElement(spUserNoticeElement, xadesPath.getCurrentSPUserNoticeNoticeRefNoticeNumbers());
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
			final Element explicitText = DomUtils.getElement(spUserNoticeElement, xadesPath.getCurrentSPUserNoticeExplicitText());
			if (explicitText != null) {
				userNotice.setExplicitText(explicitText.getTextContent());
			}

			return userNotice;

		} catch (Exception e) {
			LOG.warn("Unable to build SPUserNotice qualifier. Reason : {}", e.getMessage(), e);
			return null;
		}
	}

	private boolean isHashComputationAsInPolicySpecification(Element transforms) {
		if (transforms != null && transforms.hasChildNodes()) {
			NodeList transformList = DomUtils.getNodeList(transforms, XMLDSigPath.TRANSFORM_PATH);
			if (transformList.getLength() == 1) {
				Node transform = transformList.item(0);
				String algorithm = DomUtils.getValue(transform, "@Algorithm");
                return DSSXMLUtils.SP_DOC_DIGEST_AS_IN_SPECIFICATION_ALGORITHM_URI.equals(algorithm);
			}
		}
		return false;
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {

		NodeList nodeList = DomUtils.getNodeList(signatureElement, xadesPath.getSignatureProductionPlacePath());
		if ((nodeList.getLength() == 0) || (nodeList.item(0) == null)) {
			String signatureProductionPlaceV2Path = xadesPath.getSignatureProductionPlaceV2Path();
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
		String signaturePolicyStorePath = xadesPath.getSignaturePolicyStorePath();
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
				String currentSPDocSpecificationPath = xadesPath.getCurrentSPDocSpecification();
				if (Utils.isStringNotEmpty(currentSPDocSpecificationPath)) {
					Element spDocSpecificationElement = DomUtils.getElement(signaturePolicyStoreElement, currentSPDocSpecificationPath);
					if (spDocSpecificationElement != null) {
						spDocSpec = buildSpDocSpecification(spDocSpecificationElement);
					}
				}
				sps.setSpDocSpecification(spDocSpec);

				String currentSignaturePolicyDocumentPath = xadesPath.getCurrentSignaturePolicyDocument();
				if (Utils.isStringNotEmpty(currentSignaturePolicyDocumentPath)) {
					String spDocB64 = DomUtils.getValue(signaturePolicyStoreElement, currentSignaturePolicyDocumentPath);
					if (Utils.isStringNotEmpty(spDocB64) && Utils.isBase64Encoded(spDocB64)) {
						sps.setSignaturePolicyContent(new InMemoryDocument(Utils.fromBase64(spDocB64)));
					}
				}

				String currentSigPolDocLocalURI = xadesPath.getCurrentSigPolDocLocalURI();
				if (Utils.isStringNotEmpty(currentSigPolDocLocalURI)) {
					String sigPolDocLocalURI = DomUtils.getValue(signaturePolicyStoreElement, currentSigPolDocLocalURI);
					if (Utils.isStringNotEmpty(sigPolDocLocalURI)) {
						sps.setSigPolDocLocalURI(sigPolDocLocalURI);
					}
				}

				return sps;
			}
		}
		return null;
	}

	private SpDocSpecification buildSpDocSpecification(Element spDocSpecificationElement) {
		SpDocSpecification spDocSpec = new SpDocSpecification();

		Element identifierElement = DomUtils.getElement(spDocSpecificationElement, xadesPath.getCurrentIdentifier());
		if (identifierElement != null) {
			String spDocSpecId = identifierElement.getTextContent();

			ObjectIdentifierQualifier qualifier = null;
			String qualifierString = identifierElement.getAttribute(XAdES132Attribute.QUALIFIER.getAttributeName());
			if (Utils.isStringNotBlank(qualifierString)) {
				qualifier = ObjectIdentifierQualifier.fromValue(qualifierString);
				spDocSpec.setQualifier(qualifier);
			}

			spDocSpec.setId(DSSUtils.getObjectIdentifierValue(spDocSpecId, qualifier));
		}

		String description = DomUtils.getValue(spDocSpecificationElement, xadesPath.getCurrentDescription());
		if (Utils.isStringNotBlank(description)) {
			spDocSpec.setDescription(description);
		}

		String currentDocumentationReferenceElementsPath = xadesPath.getCurrentDocumentationReferenceElements();
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
		String signedAssertionPath = xadesPath.getSignedAssertionPath();
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
		NodeList nodeList = DomUtils.getNodeList(signatureElement, xadesPath.getClaimedRolePath());
		if (nodeList.getLength() == 0) {
			String claimedRoleV2Path = xadesPath.getClaimedRoleV2Path();
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
		/*
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
		NodeList nodeList = DomUtils.getNodeList(signatureElement, xadesPath.getCertifiedRolePath());
		if (nodeList.getLength() == 0) {
			String certifiedRoleV2Path = xadesPath.getCertifiedRoleV2Path();
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
		final NodeList allContentTypes = DomUtils.getNodeList(signatureElement, xadesPath.getDataObjectFormatObjectIdentifier());
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
		final NodeList allMimeTypes = DomUtils.getNodeList(signatureElement, xadesPath.getDataObjectFormatMimeType());
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
		Element signatureValueElement = DomUtils.getElement(signatureElement, XMLDSigPath.SIGNATURE_VALUE_PATH);
		if (signatureValueElement != null) {
			return signatureValueElement.getTextContent();
		}
		return null;
	}

	@Override
	public byte[] getSignatureValue() {
		String signatureValueBase64 = getSignatureValueBase64();
		if (signatureValueBase64 != null && Utils.isBase64Encoded(signatureValueBase64)) {
			return Utils.fromBase64(signatureValueBase64);
		} else {
			if (LOG.isDebugEnabled()) {
				LOG.warn("The signature value is not represented by a base64-encoded string! Found value : '{}'", signatureValueBase64);
			} else {
				LOG.warn("The signature value is not represented by a base64-encoded string!");
			}
		}
		return null;
	}

	/**
	 * Returns Id of the ds:SignatureValue element
	 *
	 * @return {@link String} Id
	 */
	public String getSignatureValueId() {
		return DomUtils.getValue(signatureElement, XMLDSigPath.SIGNATURE_VALUE_ID_PATH);
	}

	/**
	 * This method returns the list of ds:Object elements for the current signature element.
	 *
	 * @return {@link NodeList}
	 */
	public NodeList getObjects() {
		return DomUtils.getNodeList(signatureElement, XMLDSigPath.OBJECT_PATH);
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
	protected XAdESBaselineRequirementsChecker createBaselineRequirementsChecker(CertificateVerifier certificateVerifier) {
		return new XAdESBaselineRequirementsChecker(this, certificateVerifier);
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
			String errorMessage = "checkSignatureIntegrity : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, e.getMessage());
			}
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
							
					if (isElementReference && DSSXMLUtils.isSignedProperties(reference, xadesPath)) {
						validation.setType(DigestMatcherType.SIGNED_PROPERTIES);
						found = found && (disableXSWProtection || findSignedPropertiesById(uri));
						
					} else if (DomUtils.isXPointerQuery(uri)) {
						validation.setType(DigestMatcherType.XPOINTER);
						// found is checked in the reference validation
						
					} else if (DSSXMLUtils.isCounterSignature(reference, xadesPath)) {
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
						Element manifestElement = DSSXMLUtils.getManifestById(signatureElement, uri);
						found = found && (disableXSWProtection || (manifestElement != null));
						if (manifestElement != null) {
							validation.getDependentValidations().addAll(getManifestReferences(manifestElement));
						}
						
					}
					
					if (found && !isDuplicated) {
						intact = reference.verify();
					}

					if (LOG.isTraceEnabled()) {
						LOG.trace("Reference validation output: ");
						LOG.trace(new String(reference.getReferencedBytes()));
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
	 * <p>
	 * In case of XAdES signatures, the input of the digest value computation shall be the result of applying the
	 * canonicalization algorithm identified within the CanonicalizationMethod child element's value to the
	 * corresponding ds:Signature element and its contents. The canonicalization shall be computed keeping this
	 * ds:Signature element as a descendant of the XML root element, without detaching it.
	 */
	@Override
	public SignatureDigestReference getSignatureDigestReference(DigestAlgorithm digestAlgorithm) {
		DSSMessageDigest digest = DSSXMLUtils.getDigestOnCanonicalizedNode(signatureElement, digestAlgorithm, DEFAULT_CANONICALIZATION_METHOD);
		return new SignatureDigestReference(DEFAULT_CANONICALIZATION_METHOD, digest);
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
		String canonicalizationMethod = DomUtils.getValue(signedInfo, XMLDSigPath.CANONICALIZATION_ALGORITHM_PATH);
		if (Utils.isStringEmpty(canonicalizationMethod)) {
			LOG.warn("Canonicalization method is not present in SignedInfo element! Unable to compute DTBSR.");
			return null;
		}
		return DSSXMLUtils.getDigestOnCanonicalizedNode(signedInfo, digestAlgorithm, canonicalizationMethod);
	}

	/**
	 * Returns the ds:SignedInfo element
	 *
	 * @return {@link Element} ds:SignedInfo
	 */
	public Element getSignedInfo() {
		try {
			return DomUtils.getElement(signatureElement, XMLDSigPath.SIGNED_INFO_PATH);
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
			String signedPropertiesById = xadesPath.getSignedPropertiesPath() + DomUtils.getXPathByIdAttribute(uri);
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
			String objectById = XMLDSigPath.OBJECT_PATH + DomUtils.getXPathByIdAttribute(id);
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
			String manifestById = XMLDSigPath.MANIFEST_PATH + DomUtils.getXPathByIdAttribute(id);
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
			throw new DSSException(String.format("Unable to initialize Santuario XMLSignature. Reason : %s", e.getMessage()), e);
		}
	}

	private void initDetachedSignatureResolvers(List<DSSDocument> detachedContents) {
		Element signedInfo = getSignedInfo();
		if (signedInfo != null) {
			XMLSignature xmlSignature = getSantuarioSignature();
			for (DigestAlgorithm digestAlgorithm : DSSXMLUtils.getReferenceDigestAlgos(signedInfo)) {
				xmlSignature.addResourceResolver(new DetachedSignatureResolver(detachedContents, digestAlgorithm));
			}
		}
	}
	
	/**
	 * Used for a counter signature extension only
	 */
	private void initCounterSignatureResolver(List<DSSDocument> detachedContents) {
		Element signedInfo = getSignedInfo();
		if (signedInfo != null) {
			XMLSignature xmlSignature = getSantuarioSignature();
			List<String> types = DSSXMLUtils.getReferenceTypes(signedInfo);
			for (String type : types) {
				if (xadesPath.getCounterSignatureUri().equals(type)) {
					for (DSSDocument document : detachedContents) {
						// only one SignatureValue document shall be provided
						if (isDetachedSignatureValueDocument(document)) {
							xmlSignature.addResourceResolver(new CounterSignatureResolver(document));
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
	 * <p>
	 * 7.2.4.1 Countersignature identifier in Type attribute of ds:Reference
	 * <p>
	 * A XAdES signature containing a ds:Reference element whose Type attribute has value
	 * "http://uri.etsi.org/01903#CountersignedSignature" will indicate that
	 * is is, in fact, a countersignature of the signature referenced by this element.
	 * <p>
	 * 7.2.4.2 Enveloped countersignatures: the CounterSignature element
	 * <p>
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
				xadesPath.getCounterSignaturePath());
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
		return DomUtils.getChildrenNames(signatureElement, xadesPath.getUnsignedSignaturePropertiesPath());
	}

	/**
	 * Retrieves the name of each node found under the SignedSignatureProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getSignedSignatureProperties() {
		return DomUtils.getChildrenNames(signatureElement, xadesPath.getSignedSignaturePropertiesPath());
	}

	/**
	 * Retrieves the name of each node found under the SignedProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getSignedProperties() {
		return DomUtils.getChildrenNames(signatureElement, xadesPath.getSignedPropertiesPath());
	}

	/**
	 * Retrieves the name of each node found under the UnsignedProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getUnsignedProperties() {
		return DomUtils.getChildrenNames(signatureElement, xadesPath.getUnsignedPropertiesPath());
	}

	/**
	 * Retrieves the name of each node found under the SignedDataObjectProperties element
	 *
	 * @return an ArrayList containing the retrieved node names
	 */
	public List<String> getSignedDataObjectProperties() {
		return DomUtils.getChildrenNames(signatureElement, xadesPath.getSignedDataObjectPropertiesPath());
	}

	@Override
	public SignatureLevel getDataFoundUpToLevel() {
		if (!hasBESProfile()) {
			return SignatureLevel.XML_NOT_ETSI;
		}

		boolean baselineProfile = hasBProfile();

		if (!hasExtendedTProfile()) {
			if (baselineProfile) {
				return SignatureLevel.XAdES_BASELINE_B;
			} else if (hasEPESProfile()) {
				return SignatureLevel.XAdES_EPES;
			}
			return SignatureLevel.XAdES_BES;
		}

		baselineProfile = baselineProfile && hasTProfile();

		if (baselineProfile && hasLTProfile()) {
			if (hasERSProfile()) {
				return SignatureLevel.XAdES_ERS;
			}
			if (hasLTAProfile()) {
				return SignatureLevel.XAdES_BASELINE_LTA;
			}
			return SignatureLevel.XAdES_BASELINE_LT;

		} else if (hasCProfile()) {
			if (hasXLProfile()) {
				if (hasERSProfile()) {
					return SignatureLevel.XAdES_ERS;
				}
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

		} else if (hasXLProfile()) {
			if (hasERSProfile()) {
				return SignatureLevel.XAdES_ERS;
			}
			if (hasAProfile()) {
				return SignatureLevel.XAdES_A; // XAdES-E-A can be built on XAdES-E-T directly
			}
			return SignatureLevel.XAdES_LT;
		}

		return baselineProfile ? SignatureLevel.XAdES_BASELINE_T : SignatureLevel.XAdES_T;
	}

	@Override
	public List<String> validateStructure() {
		final XAdESStructureValidator structureValidator = XAdESStructureValidatorFactory.getInstance().fromXAdESSignature(this);
		structureValidator.validate();
		return structureValidator.getValidationErrors();
	}

	@Override
	protected List<SignatureScope> findSignatureScopes() {
		return new XAdESSignatureScopeFinder().findSignatureScope(this);
	}

	@Override
	public List<CommitmentTypeIndication> getCommitmentTypeIndications() {
		List<CommitmentTypeIndication> result = null;
		NodeList nodeList = DomUtils.getNodeList(signatureElement, xadesPath.getCommitmentTypeIndicationPath());
		if (nodeList != null && nodeList.getLength() > 0) {
			result = new ArrayList<>();
			for (int ii = 0; ii < nodeList.getLength(); ii++) {
				Node commitmentTypeIndicationNode = nodeList.item(ii);
				Element identifier = DomUtils.getElement(commitmentTypeIndicationNode, xadesPath.getCurrentCommitmentIdentifierPath());

				String uri = identifier.getTextContent();
				if (uri == null) {
					LOG.warn("The Identifier for a CommitmentTypeIndication is not defined! The CommitmentType is skipped.");
					continue;
				}

				ObjectIdentifierQualifier qualifier = null;
				String qualifierString = identifier.getAttribute(XAdES132Attribute.QUALIFIER.getAttributeName());
				if (Utils.isStringNotBlank(qualifierString)) {
					qualifier = ObjectIdentifierQualifier.fromValue(qualifierString);
				}

				uri = DSSUtils.getObjectIdentifierValue(uri, qualifier);

				final CommitmentTypeIndication commitmentTypeIndication = new CommitmentTypeIndication(uri);
				
				final Element descriptionNode = DomUtils.getElement(commitmentTypeIndicationNode,
						xadesPath.getCurrentCommitmentDescriptionPath());
				if (descriptionNode != null) {
					commitmentTypeIndication.setDescription(descriptionNode.getTextContent());
				}
				final Element docRefsNode = DomUtils.getElement(commitmentTypeIndicationNode,
						xadesPath.getCurrentCommitmentDocumentationReferencesPath());
				if (docRefsNode != null) {
					commitmentTypeIndication.setDocumentReferences(getDocumentationReferences(docRefsNode));
				}

				final Element allSignedDataObjectsNode = DomUtils.getElement(commitmentTypeIndicationNode,
						xadesPath.getCurrentCommitmentAllSignedDataObjectsPath());
				if (allSignedDataObjectsNode != null) {
					commitmentTypeIndication.setAllDataSignedObjects(true);
				} else {
					final NodeList commitmentObjectReferencesNodeList = DomUtils.getNodeList(commitmentTypeIndicationNode,
							xadesPath.getCurrentCommitmentObjectReferencesPath());
					if (commitmentObjectReferencesNodeList != null && commitmentObjectReferencesNodeList.getLength() > 0) {
						commitmentTypeIndication.setObjectReferences(getObjectReferences(commitmentObjectReferencesNodeList));
					}
				}

				result.add(commitmentTypeIndication);
			}
		}
		return result;
	}
	
	private List<String> getDocumentationReferences(Element docRefsNode) {
		final NodeList docRefsChildNodes = DomUtils.getNodeList(docRefsNode, xadesPath.getCurrentDocumentationReference());
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

	private List<String> getObjectReferences(NodeList commitmentObjectReferencesNodeList) {
		List<String> signedDataObjects = new ArrayList<>();
		for (int i = 0; i < commitmentObjectReferencesNodeList.getLength(); i++) {
			signedDataObjects.add(DomUtils.getId(commitmentObjectReferencesNodeList.item(i).getTextContent()));
		}
		return signedDataObjects;
	}

	/**
	 * Gets a list of found references
	 *
	 * @return a list of {@link Reference}s
	 */
	public List<Reference> getReferences() {
		if (references == null) {
			XMLSignature xmlSignature = getSantuarioSignature();
			SignedInfo signedInfo = xmlSignature.getSignedInfo();
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
		final NodeList list = DomUtils.getNodeList(signatureElement, XMLDSigPath.OBJECT_PATH);
		final List<Element> objectElements = new ArrayList<>(list.getLength());
		for (int ii = 0; ii < list.getLength(); ii++) {
			final Node node = list.item(ii);
			final Element element = (Element) node;
			if (DomUtils.getElement(element, xadesPath.getSignedPropertiesPath()) != null) {
				// ignore signed properties
				continue;
			}
			objectElements.add(element);
		}
		return objectElements;
	}

	/**
	 * This method allows to register a new {@code XAdESPaths}.
	 *
	 * @param xadesPaths
	 *                   {@code XAdESPaths} to register
	 */
	public void registerXAdESPaths(final XAdESPath xadesPaths) {
		xadesPathHolders.add(xadesPaths);
	}

}
