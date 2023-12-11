package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.SignatureAttributeIdentifier;
import org.bouncycastle.asn1.cms.Attribute;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Represents a unique identifier for an attribute from a CAdES signature
 *
 */
public class CAdESAttributeIdentifier extends SignatureAttributeIdentifier {

    private static final long serialVersionUID = -1244583446667611418L;

    /**
     * Default constructor
     *
     * @param data byte array to compute the identifier
     */
    CAdESAttributeIdentifier(byte[] data) {
        super(data);
    }

    /**
     * Builds the identifier for CAdES attribute
     *
     * @param attribute {@link Attribute}
     * @return {@link CAdESAttributeIdentifier}
     * @deprecated since DSS 5.13. Please use {@code #build(Attribute attribute, Integer order)}
     */
    @Deprecated
    public static CAdESAttributeIdentifier build(Attribute attribute) {
        return build(attribute, null);
    }

    /**
     * Builds the identifier for CAdES attribute
     *
     * @param attribute {@link Attribute}
     * @param order position of the attribute within signature properties
     * @return {@link CAdESAttributeIdentifier}
     */
    public static CAdESAttributeIdentifier build(Attribute attribute, Integer order) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
            if (attribute != null) {
                // attribute identifier + value
                dos.write(attribute.getEncoded());
            }
            if (order != null) {
                dos.write(order);
            }
            dos.flush();

            return new CAdESAttributeIdentifier(baos.toByteArray());

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to build a CAdESAttributeIdentifier. Reason : %s", e.getMessage()), e);
        }
    }

}
