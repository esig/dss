
package eu.europa.ec.markt.dss.ws.signature;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for encryptionAlgorithm.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="encryptionAlgorithm">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="RSA"/>
 *     &lt;enumeration value="DSA"/>
 *     &lt;enumeration value="ECDSA"/>
 *     &lt;enumeration value="HMAC"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "encryptionAlgorithm")
@XmlEnum
public enum EncryptionAlgorithm {

    RSA,
    DSA,
    ECDSA,
    HMAC;

    public String value() {
        return name();
    }

    public static EncryptionAlgorithm fromValue(String v) {
        return valueOf(v);
    }

}
