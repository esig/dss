
package eu.europa.ec.markt.dss.ws.signature;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for signaturePackaging.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="signaturePackaging">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="ENVELOPED"/>
 *     &lt;enumeration value="ENVELOPING"/>
 *     &lt;enumeration value="DETACHED"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "signaturePackaging")
@XmlEnum
public enum SignaturePackaging {

    ENVELOPED,
    ENVELOPING,
    DETACHED;

    public String value() {
        return name();
    }

    public static SignaturePackaging fromValue(String v) {
        return valueOf(v);
    }

}
