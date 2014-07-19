
package eu.europa.ec.markt.dss.ws.signature;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for signatureLevel.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="signatureLevel">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="XMLDSIG"/>
 *     &lt;enumeration value="XAdES_C"/>
 *     &lt;enumeration value="XAdES_X"/>
 *     &lt;enumeration value="XAdES_XL"/>
 *     &lt;enumeration value="XAdES_A"/>
 *     &lt;enumeration value="XAdES_BASELINE_LTA"/>
 *     &lt;enumeration value="XAdES_BASELINE_LT"/>
 *     &lt;enumeration value="XAdES_BASELINE_T"/>
 *     &lt;enumeration value="XAdES_BASELINE_B"/>
 *     &lt;enumeration value="CAdES_BASELINE_LTA"/>
 *     &lt;enumeration value="CAdES_BASELINE_LT"/>
 *     &lt;enumeration value="CAdES_BASELINE_T"/>
 *     &lt;enumeration value="CAdES_BASELINE_B"/>
 *     &lt;enumeration value="CAdES_101733_C"/>
 *     &lt;enumeration value="CAdES_101733_X"/>
 *     &lt;enumeration value="CAdES_101733_A"/>
 *     &lt;enumeration value="PAdES_BASELINE_LTA"/>
 *     &lt;enumeration value="PAdES_BASELINE_LT"/>
 *     &lt;enumeration value="PAdES_BASELINE_T"/>
 *     &lt;enumeration value="PAdES_BASELINE_B"/>
 *     &lt;enumeration value="PAdES_102778_LTV"/>
 *     &lt;enumeration value="ASiC_S_BASELINE_LTA"/>
 *     &lt;enumeration value="ASiC_S_BASELINE_LT"/>
 *     &lt;enumeration value="ASiC_S_BASELINE_T"/>
 *     &lt;enumeration value="ASiC_S_BASELINE_B"/>
 *     &lt;enumeration value="ASiC_E_BASELINE_LTA"/>
 *     &lt;enumeration value="ASiC_E_BASELINE_LT"/>
 *     &lt;enumeration value="ASiC_E_BASELINE_T"/>
 *     &lt;enumeration value="ASiC_E_BASELINE_B"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "signatureLevel")
@XmlEnum
public enum SignatureLevel {

    XMLDSIG("XMLDSIG"),
    @XmlEnumValue("XAdES_C")
    XAdES_C("XAdES_C"),
    @XmlEnumValue("XAdES_X")
    XAdES_X("XAdES_X"),
    @XmlEnumValue("XAdES_XL")
    XAdES_XL("XAdES_XL"),
    @XmlEnumValue("XAdES_A")
    XAdES_A("XAdES_A"),
    @XmlEnumValue("XAdES_BASELINE_LTA")
    XAdES_BASELINE_LTA("XAdES_BASELINE_LTA"),
    @XmlEnumValue("XAdES_BASELINE_LT")
    XAdES_BASELINE_LT("XAdES_BASELINE_LT"),
    @XmlEnumValue("XAdES_BASELINE_T")
    XAdES_BASELINE_T("XAdES_BASELINE_T"),
    @XmlEnumValue("XAdES_BASELINE_B")
    XAdES_BASELINE_B("XAdES_BASELINE_B"),
    @XmlEnumValue("CAdES_BASELINE_LTA")
    CAdES_BASELINE_LTA("CAdES_BASELINE_LTA"),
    @XmlEnumValue("CAdES_BASELINE_LT")
    CAdES_BASELINE_LT("CAdES_BASELINE_LT"),
    @XmlEnumValue("CAdES_BASELINE_T")
    CAdES_BASELINE_T("CAdES_BASELINE_T"),
    @XmlEnumValue("CAdES_BASELINE_B")
    CAdES_BASELINE_B("CAdES_BASELINE_B"),
    @XmlEnumValue("CAdES_101733_C")
    CAdES_101733_C("CAdES_101733_C"),
    @XmlEnumValue("CAdES_101733_X")
    CAdES_101733_X("CAdES_101733_X"),
    @XmlEnumValue("CAdES_101733_A")
    CAdES_101733_A("CAdES_101733_A"),
    @XmlEnumValue("PAdES_BASELINE_LTA")
    PAdES_BASELINE_LTA("PAdES_BASELINE_LTA"),
    @XmlEnumValue("PAdES_BASELINE_LT")
    PAdES_BASELINE_LT("PAdES_BASELINE_LT"),
    @XmlEnumValue("PAdES_BASELINE_T")
    PAdES_BASELINE_T("PAdES_BASELINE_T"),
    @XmlEnumValue("PAdES_BASELINE_B")
    PAdES_BASELINE_B("PAdES_BASELINE_B"),
    @XmlEnumValue("PAdES_102778_LTV")
    PAdES_102778_LTV("PAdES_102778_LTV"),
    @XmlEnumValue("ASiC_S_BASELINE_LTA")
    ASiC_S_BASELINE_LTA("ASiC_S_BASELINE_LTA"),
    @XmlEnumValue("ASiC_S_BASELINE_LT")
    ASiC_S_BASELINE_LT("ASiC_S_BASELINE_LT"),
    @XmlEnumValue("ASiC_S_BASELINE_T")
    ASiC_S_BASELINE_T("ASiC_S_BASELINE_T"),
    @XmlEnumValue("ASiC_S_BASELINE_B")
    ASiC_S_BASELINE_B("ASiC_S_BASELINE_B"),
    @XmlEnumValue("ASiC_E_BASELINE_LTA")
    ASiC_E_BASELINE_LTA("ASiC_E_BASELINE_LTA"),
    @XmlEnumValue("ASiC_E_BASELINE_LT")
    ASiC_E_BASELINE_LT("ASiC_E_BASELINE_LT"),
    @XmlEnumValue("ASiC_E_BASELINE_T")
    ASiC_E_BASELINE_T("ASiC_E_BASELINE_T"),
    @XmlEnumValue("ASiC_E_BASELINE_B")
    ASiC_E_BASELINE_B("ASiC_E_BASELINE_B");
    private final String value;

    SignatureLevel(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static SignatureLevel fromValue(String v) {
        for (SignatureLevel c: SignatureLevel.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
