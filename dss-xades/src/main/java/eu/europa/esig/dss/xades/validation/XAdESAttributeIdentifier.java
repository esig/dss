package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.SignatureAttributeIdentifier;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Represents an identifier of a XAdES Attribute
 */
public class XAdESAttributeIdentifier extends SignatureAttributeIdentifier {

    private static final long serialVersionUID = 178331193990451357L;

    /**
     * Default constructor
     *
     * @param data byte array
     */
    XAdESAttributeIdentifier(byte[] data) {
        super(data);
    }

    /**
     * Builds the {@code XAdESAttributeIdentifier} from the given property {@code Node}
     *
     * @param node {@link Node}
     * @return {@link XAdESAttributeIdentifier}
     */
    public static XAdESAttributeIdentifier build(Node node) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
            dos.write(getBinaries(node));
            dos.writeInt(getOrder(node));

            return new XAdESAttributeIdentifier(baos.toByteArray());

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to build a XAdES Attribute Identifier : %s", e.getMessage()), e);
        }
    }

    private static byte[] getBinaries(Node node) {
        return DSSXMLUtils.serializeNode(node);
    }

    private static int getOrder(Node node) {
        Node parentNode = node.getParentNode();
        if (parentNode != null) {
            NodeList childNodes = parentNode.getChildNodes();
            for (int ii = 0; ii < childNodes.getLength(); ii++) {
                Node child = childNodes.item(ii);
                if (node == child) {
                    return ii;
                }
            }
        }
        return 0;
    }

}
