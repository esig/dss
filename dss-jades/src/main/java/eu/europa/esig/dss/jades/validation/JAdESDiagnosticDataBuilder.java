package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentDiagnosticDataBuilder;

/**
 * DiagnosticDataBuilder for a JWS signature
 *
 */
public class JAdESDiagnosticDataBuilder extends SignedDocumentDiagnosticDataBuilder {

    /**
     * Default constructor
     */
    public JAdESDiagnosticDataBuilder() {
        // empty
    }

    @Override
    public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
        XmlSignature xmlSignature = super.buildDetachedXmlSignature(signature);
        JAdESSignature jadesSignature = (JAdESSignature) signature;
        xmlSignature.setSignatureType(jadesSignature.getSignatureType());
        return xmlSignature;
    }

}
