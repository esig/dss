
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
