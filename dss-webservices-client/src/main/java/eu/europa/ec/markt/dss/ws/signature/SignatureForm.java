
package eu.europa.ec.markt.dss.ws.signature;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for signatureForm.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="signatureForm">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="XAdES"/>
 *     &lt;enumeration value="CAdES"/>
 *     &lt;enumeration value="PAdES"/>
 *     &lt;enumeration value="ASiC_S"/>
 *     &lt;enumeration value="ASiC_E"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "signatureForm")
@XmlEnum
public enum SignatureForm {

    @XmlEnumValue("XAdES")
    XAdES("XAdES"),
    @XmlEnumValue("CAdES")
    CAdES("CAdES"),
    @XmlEnumValue("PAdES")
    PAdES("PAdES"),
    @XmlEnumValue("ASiC_S")
    ASiC_S("ASiC_S"),
    @XmlEnumValue("ASiC_E")
    ASiC_E("ASiC_E");
    private final String value;

    SignatureForm(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static SignatureForm fromValue(String v) {
        for (SignatureForm c: SignatureForm.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
