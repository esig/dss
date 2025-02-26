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
package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.trustedlist.TrustedList211Utils;
import eu.europa.esig.trustedlist.TrustedListUtils;
import eu.europa.esig.trustedlist.definition.TrustedListNamespace;
import eu.europa.esig.xades.definition.XAdESElement;
import eu.europa.esig.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.xmldsig.definition.XMLDSigElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.transform.dom.DOMSource;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class verifies conformity of a TL to the defined TLVersion.
 * NOTE: The class currently handles validation of only V5 and V6 Trusted List versions.
 *
 */
public class TLStructureVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(TLStructureVerifier.class);

    private final static String TRUSTED_LIST_PARENT_ELEMENT = "TrustServiceStatusList";

    /** List of acceptable TL versions */
    private List<Integer> acceptedTLVersions;

    /** Defines whether the current validation of the XML Trusted List is performed for signing */
    private boolean signingMode;

    static {
        DomUtils.registerNamespace(TrustedListNamespace.NS);
    }

    /**
     * Default constructor.
     * Accepts TL V5 and TL V6
     */
    public TLStructureVerifier() {
        // empty
    }

    /**
     * Sets a list of acceptable TL version.
     * When defined, an error message will be produces for Trusted Lists with a different version.
     *
     * @param acceptedTLVersions a list of {@link Integer}s, containing acceptable TL versions
     * @return this {@link TLStructureVerifier}
     */
    public TLStructureVerifier setAcceptedTLVersions(List<Integer> acceptedTLVersions) {
        this.acceptedTLVersions = acceptedTLVersions;
        return this;
    }

    /**
     * Sets whether the current operation is the XML Trusted List signing.
     * If enabled, verifies that no ds:Signature element is present within the XML Trusted List.
     * Otherwise, verifies presence and validity of the ds:Signature element.
     * Default : FALSE (verifies that the signature is not present)
     *
     * @param signingMode whether the validation is performed for the XML Trusted List signing
     * @return this {@link TLStructureVerifier}
     */
    public TLStructureVerifier setSigningMode(boolean signingMode) {
        this.signingMode = signingMode;
        return this;
    }

    /**
     * This method validates the Trusted List's conformity to the specified TLVersion
     *
     * @param dssDocument {@link DSSDocument} XML Trusted List to be validated
     * @param tlVersion {@link Integer} the version of the Trusted List to validate {@code document} against
     * @return a list of {@link String}s indicating errors occurred during the conformity evaluation
     */
    public List<String> validate(final DSSDocument dssDocument, final Integer tlVersion) {
        Objects.requireNonNull(dssDocument, "Document to be validated cannot be null!");
        return validate(DomUtils.buildDOM(dssDocument), tlVersion);
    }

    /**
     * This method validates the Trusted List's conformity to the specified TLVersion
     *
     * @param document {@link Document} XML Trusted List to be validated
     * @param tlVersion {@link Integer} the version of the Trusted List to validate {@code document} against
     * @return a list of {@link String}s indicating errors occurred during the conformity evaluation
     */
    public List<String> validate(final Document document, final Integer tlVersion) {
        Objects.requireNonNull(document, "Document to be validated cannot be null!");
        if (tlVersion == null) {
            return Collections.singletonList("No TLVersion has been found!");
        }

        if (Utils.isCollectionEmpty(acceptedTLVersions)) {
            LOG.debug("No acceptable TL Versions have been defined. The structural validation is skipped.");
            return Collections.emptyList();
        }

        final List<String> errors = new ArrayList<>();
        errors.addAll(validateNamespace(document));

        if (!acceptedTLVersions.contains(tlVersion)) {
            errors.add(String.format("The TL Version '%s' is not acceptable!", tlVersion));

        } else if (XAdESTrustedListUtils.TL_V5_IDENTIFIER.equals(tlVersion)) {
            errors.addAll(validateTrustedListV5(document));
        } else if (XAdESTrustedListUtils.TL_V6_IDENTIFIER.equals(tlVersion)) {
            errors.addAll(validateTrustedListV6(document));
        }

        return errors;
    }

    /**
     * This method validates the Trusted List XML document against the TL V5 definition
     *
     * @param document {@link Document} containing a Trusted List to be validated
     * @return a list of {@link String}s
     */
    protected List<String> validateTrustedListV5(Document document) {
        final List<String> errors = new ArrayList<>();
        List<String> xsdValidationErrors = validateAgainstXSD(document, TrustedList211Utils.getInstance());
        if (Utils.isCollectionNotEmpty(xsdValidationErrors)) {
            errors.addAll(xsdValidationErrors);
        }
        Element signatureElement = getSignatureElement(document);
        errors.addAll(verifySignatureElementPresence(signatureElement));
        return errors;
    }

    /**
     * This method validates the Trusted List XML document against the TL V6 definition
     *
     * @param document {@link Document} containing a Trusted List to be validated
     * @return a list of {@link String}s
     */
    protected List<String> validateTrustedListV6(Document document) {
        final List<String> errors = new ArrayList<>();
        List<String> xsdValidationErrors = validateAgainstXSD(document, TrustedListUtils.getInstance());
        if (Utils.isCollectionNotEmpty(xsdValidationErrors)) {
            errors.addAll(xsdValidationErrors);
        }

        Element signatureElement = getSignatureElement(document);
        errors.addAll(verifySignatureElementPresence(signatureElement));

        List<String> v2ConformityErrors = validateSignatureElement(signatureElement, true);
        if (Utils.isCollectionNotEmpty(v2ConformityErrors)) {
            errors.addAll(v2ConformityErrors);
        }
        return errors;
    }

    private List<String> validateAgainstXSD(Document document, XSDAbstractUtils xsdUtils) {
        return xsdUtils.validateAgainstXSD(new DOMSource(document));
    }

    private List<String> validateNamespace(Document documentDom) {
        Element documentElement = documentDom.getDocumentElement();
        if (!TRUSTED_LIST_PARENT_ELEMENT.equals(documentElement.getLocalName()) ||
                !TrustedListNamespace.NS.getUri().equals(documentElement.getNamespaceURI())) {
            return Collections.singletonList(String.format("The root of XML Trusted List shall be %s:%s element!",
                    TrustedListNamespace.NS.getPrefix(), TRUSTED_LIST_PARENT_ELEMENT));
        }
        return Collections.emptyList();
    }

    private Element getSignatureElement(Document documentDom) {
        Element documentElement = documentDom.getDocumentElement();
        return getChildElement(documentElement, XMLDSigElement.SIGNATURE);
    }

    private List<String> verifySignatureElementPresence(Element dsSignature) {
        if (signingMode) {
            if (dsSignature != null) {
                return Collections.singletonList("The ds:Signature element shall not be present for XML Trusted List signing!");
            }
            // no ds:Signature is expected on signing

        } else {
            if (dsSignature == null) {
                return Collections.singletonList("No ds:Signature element is present!");
            }
        }

        return Collections.emptyList();
    }

    private List<String> validateSignatureElement(Element dsSignature, boolean v2Expected) {
        if (dsSignature == null || signingMode) {
            return Collections.emptyList();
        }

        // NOTE: manual parsing is used for performance reasons
        List<Element> objects = getChildElements(dsSignature, XMLDSigElement.OBJECT);
        if (Utils.isCollectionEmpty(objects)) {
            return Collections.singletonList("No ds:Object elements are present!");
        }
        Element qualifyingProperties = getQualifyingPropertiesElement(objects);
        if (qualifyingProperties == null) {
            return Collections.singletonList("No xades:QualifyingProperties element has been found!");
        }
        Element signedProperties = getChildElement(qualifyingProperties, XAdES132Element.SIGNED_PROPERTIES);
        if (signedProperties == null) {
            return Collections.singletonList("No xades:SignedProperties element has been found!");
        }
        Element signedSignatureProperties = getChildElement(signedProperties, XAdES132Element.SIGNED_SIGNATURE_PROPERTIES);
        if (signedSignatureProperties == null) {
            return Collections.singletonList("No xades:SignedSignatureProperties element has been found!");
        }

        final List<String> errorMessages = new ArrayList<>();

        List<Element> signingCertificateElements = getMultipleElements(signedSignatureProperties,
                XAdES132Element.SIGNING_CERTIFICATE, XAdES132Element.SIGNING_CERTIFICATE_V2);
        if (Utils.isCollectionNotEmpty(signingCertificateElements)) {
            for (Element signingCertificate : signingCertificateElements) {
                if (v2Expected ^ doesMatch(signingCertificate, XAdES132Element.SIGNING_CERTIFICATE_V2)) {
                    errorMessages.add(String.format("%s element shall not be present!", signingCertificate.getLocalName()));
                }
            }
        } else {
            errorMessages.add(String.format("No xades:SigningCertificate%s element has been found!", v2Expected ? "V2" : ""));
        }

        List<Element> signatureProductionPlaceElements = getMultipleElements(signedSignatureProperties,
                XAdES132Element.SIGNATURE_PRODUCTION_PLACE, XAdES132Element.SIGNATURE_PRODUCTION_PLACE_V2);
        if (Utils.isCollectionNotEmpty(signatureProductionPlaceElements)) {
            for (Element signatureProductionPlace : signatureProductionPlaceElements) {
                if (v2Expected ^ doesMatch(signatureProductionPlace, XAdES132Element.SIGNATURE_PRODUCTION_PLACE_V2)) {
                    errorMessages.add(String.format("%s element shall not be present!", signatureProductionPlace.getLocalName()));
                }
            }
        }

        List<Element> signerRoleElements = getMultipleElements(signedSignatureProperties,
                XAdES132Element.SIGNER_ROLE, XAdES132Element.SIGNER_ROLE_V2);
        if (Utils.isCollectionNotEmpty(signerRoleElements)) {
            for (Element signerRole : signerRoleElements) {
                if (v2Expected ^ doesMatch(signerRole, XAdES132Element.SIGNER_ROLE_V2)) {
                    errorMessages.add(String.format("%s element shall not be present!", signerRole.getLocalName()));
                }
            }
        }

        return errorMessages;
    }

    private Element getQualifyingPropertiesElement(List<Element> objects) {
        for (Element object : objects) {
            Element qualifyingProperties = getChildElement(object, XAdES132Element.QUALIFYING_PROPERTIES);
            if (qualifyingProperties != null) {
                return qualifyingProperties;
            }
        }
        return null;
    }

    private List<Element> getMultipleElements(Element signedSignatureProperties, XAdESElement... targetElements) {
        final List<Element> result = new ArrayList<>();
        for (XAdESElement targetElement : targetElements) {
            List<Element> signingCertificates = getChildElements(signedSignatureProperties, targetElement);
            if (Utils.isCollectionNotEmpty(signingCertificates)) {
                result.addAll(signingCertificates);
            }
        }
        return result;
    }

    private Element getChildElement(Element parentElement, DSSElement targetElement) {
        List<Element> childrenList = getChildElements(parentElement, targetElement);
        if (Utils.collectionSize(childrenList) == 1) {
            return childrenList.get(0);
        }
        return null;
    }

    private List<Element> getChildElements(Element parentElement, DSSElement targetElement) {
        final List<Element> children = new ArrayList<>();
        NodeList childNodes = parentElement.getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node childNode = childNodes.item(i);
            if (Node.ELEMENT_NODE == childNode.getNodeType()) {
                Element childElement = (Element) childNode;
                if (doesMatch(childElement, targetElement)) {
                    children.add(childElement);
                }
            }
        }
        return children;
    }

    private boolean doesMatch(Element element, DSSElement dssElement) {
        return dssElement.isSameTagName(element.getLocalName()) && dssElement.getURI().equals(element.getNamespaceURI());
    }

}
