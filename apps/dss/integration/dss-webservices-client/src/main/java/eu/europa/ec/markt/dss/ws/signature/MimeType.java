
package eu.europa.ec.markt.dss.ws.signature;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for mimeType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="mimeType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="BINARY"/>
 *     &lt;enumeration value="XML"/>
 *     &lt;enumeration value="PDF"/>
 *     &lt;enumeration value="PKCS7"/>
 *     &lt;enumeration value="ASICS"/>
 *     &lt;enumeration value="TEXT"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "mimeType")
@XmlEnum
public enum MimeType {

    BINARY("BINARY"),
    XML("XML"),
    PDF("PDF"),
    @XmlEnumValue("PKCS7")
    PKCS7("PKCS7"),
    ASICS("ASICS"),
    TEXT("TEXT");
    private final String value;

    MimeType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static MimeType fromValue(String v) {
        for (MimeType c: MimeType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
