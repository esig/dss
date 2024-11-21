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

/**
 * This class verified conformity of a TL to the defined TLVersion
 *
 */
public class TLConformityValidator {

    private static final Logger LOG = LoggerFactory.getLogger(TLConformityValidator.class);

    /** Identifier used for a TL version 5 */
    private static final Integer TL_V5_IDENTIFIER = 5;

    /** Identifier used for a TL version 6 */
    private static final Integer TL_V6_IDENTIFIER = 6;

    /** The TL XML document */
    private final DSSDocument document;

    /** Target version of the Trusted List to validate conformity to */
    private final Integer tlVersion;

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} XML TL document, to be verified
     * @param tlVersion {@link Integer} the version of the Trusted List to validate {@code document} against
     */
    public TLConformityValidator(final DSSDocument document, final Integer tlVersion) {
        this.document = document;
        this.tlVersion = tlVersion;
    }

    /**
     * This method validates the Trusted List's conformity to the specified TLVersion
     *
     * @return a list of {@link String}s indicating errors occurred during the conformity evaluation
     */
    public List<String> validate() {
        final List<String> errors = new ArrayList<>();

        if (tlVersion == null) {
            errors.add("No TLVersion has been found!");
            return errors;
        }

        if (TL_V5_IDENTIFIER.equals(tlVersion)) {
            List<String> xsdValidationErrors = validateAgainstXSD(TrustedList211Utils.getInstance());
            if (Utils.isCollectionNotEmpty(xsdValidationErrors)) {
                errors.addAll(xsdValidationErrors);
            }

        } else if (TL_V6_IDENTIFIER.equals(tlVersion)) {
            // XSD validation is not performed, as JAXB is used to marshall against the TLv6 XSD
            List<String> v2ConformityErrors = verifyV2ElementsPresence(true);
            if (Utils.isCollectionNotEmpty(v2ConformityErrors)) {
                errors.addAll(v2ConformityErrors);
            }

        } else {
            LOG.warn("Not supported TLVersion '{}'. Conformity validation has been skipped.", tlVersion);
        }

        return errors;
    }

    private List<String> validateAgainstXSD(XSDAbstractUtils xsdUtils) {
        try (InputStream is = document.openStream()) {
            return xsdUtils.validateAgainstXSD(new StreamSource(is));
        } catch (IOException e) {
            LOG.warn("Unable to read document on XSD validation : {}", e.getMessage(), e);
            return Collections.singletonList(String.format("Unable to verify XSD : %s", e.getMessage()));
        }
    }

    private List<String> verifyV2ElementsPresence(boolean v2Expected) {
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
