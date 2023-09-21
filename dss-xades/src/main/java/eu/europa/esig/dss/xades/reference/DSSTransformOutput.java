package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.model.DSSException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.w3c.dom.Node;

import java.io.IOException;

/**
 * Represents an {@code XMLSignatureInput} wrapper
 *
 */
public class DSSTransformOutput {

    /** The cached XMLSignatureInput */
    private final XMLSignatureInput xmlSignatureInput;

    /**
     * Default constructor to instantiate object from XMLSignatureInput
     *
     * @param xmlSignatureInput {@link XMLSignatureInput}
     */
    public DSSTransformOutput(XMLSignatureInput xmlSignatureInput) {
        this.xmlSignatureInput = xmlSignatureInput;
    }

    /**
     * Instantiates the object from a {@code Node}
     *
     * @param node {@link Node}
     */
    public DSSTransformOutput(Node node) {
        this(new XMLSignatureInput(node));
    }

    /**
     * Returns an {@code XMLSignatureInput}
     *
     * @return {@link XMLSignatureInput}
     */
    protected XMLSignatureInput getXmlSignatureInput() {
        return xmlSignatureInput;
    }

    /**
     * Returns bytes after performing transforms
     *
     * @return byte array
     */
    public byte[] getBytes() {
        try {
            return xmlSignatureInput.getBytes();
        } catch (IOException | XMLSecurityException e) {
            throw new DSSException(String.format("Cannot extract Transform output bytes. Reason : [%s]", e.getMessage()), e);
        }
    }

}
