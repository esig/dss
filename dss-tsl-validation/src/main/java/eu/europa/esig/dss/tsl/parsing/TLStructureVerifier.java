package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.definition.XAdESElement;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.trustedlist.TrustedList211Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.transform.stream.StreamSource;
import java.io.IOException;
import java.io.InputStream;
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

    /** Identifier used for a TL version 5 */
    private static final Integer TL_V5_IDENTIFIER = 5;

    /** Identifier used for a TL version 6 */
    private static final Integer TL_V6_IDENTIFIER = 6;

    /** List of acceptable TL versions */
    private List<Integer> acceptedTLVersions;

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
     * This method validates the Trusted List's conformity to the specified TLVersion
     *
     * @param document {@link DSSDocument} XML Trusted List to be validated
     * @param tlVersion {@link Integer} the version of the Trusted List to validate {@code document} against
     * @return a list of {@link String}s indicating errors occurred during the conformity evaluation
     */
    public List<String> validate(final DSSDocument document, final Integer tlVersion) {
        Objects.requireNonNull(document, "Document to be validated cannot be null!");
        if (tlVersion == null) {
            return Collections.singletonList("No TLVersion has been found!");
        }

        if (Utils.isCollectionEmpty(acceptedTLVersions)) {
            LOG.debug("No acceptable TL Versions have been defined. The structural validation is skipped.");
            return Collections.emptyList();
        }

        final List<String> errors = new ArrayList<>();

        if (!acceptedTLVersions.contains(tlVersion)) {
            errors.add(String.format("The TL Version '%s' is not acceptable!", tlVersion));

        } else if (TL_V5_IDENTIFIER.equals(tlVersion)) {
            errors.addAll(validateTrustedListV5(document));
        } else if (TL_V6_IDENTIFIER.equals(tlVersion)) {
            errors.addAll(validateTrustedListV6(document));
        }

        return errors;
    }

    /**
     * This method validates the Trusted List XML document against the TL V5 definition
     *
     * @param document {@link DSSDocument} containing a Trusted List to be validated
     * @return a list of {@link String}s
     */
    protected List<String> validateTrustedListV5(DSSDocument document) {
        List<String> xsdValidationErrors = validateAgainstXSD(document, TrustedList211Utils.getInstance());
        if (Utils.isCollectionNotEmpty(xsdValidationErrors)) {
            return xsdValidationErrors;
        }
        return Collections.emptyList();
    }

    /**
     * This method validates the Trusted List XML document against the TL V6 definition
     *
     * @param document {@link DSSDocument} containing a Trusted List to be validated
     * @return a list of {@link String}s
     */
    protected List<String> validateTrustedListV6(DSSDocument document) {
        List<String> v2ConformityErrors = verifyV2ElementsPresence(document, true);
        if (Utils.isCollectionNotEmpty(v2ConformityErrors)) {
            return v2ConformityErrors;
        }
        return Collections.emptyList();
    }

    private List<String> validateAgainstXSD(DSSDocument document, XSDAbstractUtils xsdUtils) {
        try (InputStream is = document.openStream()) {
            return xsdUtils.validateAgainstXSD(new StreamSource(is));
        } catch (IOException e) {
            LOG.warn("Unable to read document on XSD validation : {}", e.getMessage(), e);
            return Collections.singletonList(String.format("Unable to verify XSD : %s", e.getMessage()));
        }
    }

    private List<String> verifyV2ElementsPresence(DSSDocument document, boolean v2Expected) {
        // NOTE: manual parsing is used for performance reasons
        Document documentDom = DomUtils.buildDOM(document);
        Element documentElement = documentDom.getDocumentElement();

        Element dsSignature = getChildElement(documentElement, XMLDSigElement.SIGNATURE);
        if (dsSignature == null) {
            return Collections.singletonList("No ds:Signature element is present!");
        }
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
