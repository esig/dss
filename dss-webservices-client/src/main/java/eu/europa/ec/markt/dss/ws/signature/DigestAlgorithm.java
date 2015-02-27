
package eu.europa.ec.markt.dss.ws.signature;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for digestAlgorithm.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="digestAlgorithm">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="SHA1"/>
 *     &lt;enumeration value="SHA224"/>
 *     &lt;enumeration value="SHA256"/>
 *     &lt;enumeration value="SHA384"/>
 *     &lt;enumeration value="SHA512"/>
 *     &lt;enumeration value="RIPEMD160"/>
 *     &lt;enumeration value="MD2"/>
 *     &lt;enumeration value="MD5"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "digestAlgorithm")
@XmlEnum
public enum DigestAlgorithm {

    @XmlEnumValue("SHA1")
    SHA1("SHA1"),
    @XmlEnumValue("SHA224")
    SHA224("SHA224"),
    @XmlEnumValue("SHA256")
    SHA256("SHA256"),
    @XmlEnumValue("SHA384")
    SHA384("SHA384"),
    @XmlEnumValue("SHA512")
    SHA512("SHA512"),
    @XmlEnumValue("RIPEMD160")
    RIPEMD160("RIPEMD160"),
    @XmlEnumValue("MD2")
    MD2("MD2"),
    @XmlEnumValue("MD5")
    MD5("MD5");
    private final String value;

    DigestAlgorithm(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static DigestAlgorithm fromValue(String v) {
        for (DigestAlgorithm c: DigestAlgorithm.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
