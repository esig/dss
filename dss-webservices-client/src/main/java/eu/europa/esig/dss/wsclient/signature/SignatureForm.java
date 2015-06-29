
/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.wsclient.signature;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 *
 * 
 *
 *
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
