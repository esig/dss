
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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 *
 *
 *
 *
 * <pre>
 * &lt;complexType name="wsChainCertificate">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="signedAttribute" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="x509Certificate" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 *
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "wsChainCertificate", propOrder = {
		"signedAttribute",
		"x509Certificate"
})
public class WsChainCertificate {

	protected boolean signedAttribute;
	protected byte[] x509Certificate;

	/**
	 * Gets the value of the signedAttribute property.
	 *
	 */
	public boolean isSignedAttribute() {
		return signedAttribute;
	}

	/**
	 * Sets the value of the signedAttribute property.
	 *
	 */
	public void setSignedAttribute(boolean value) {
		this.signedAttribute = value;
	}

	/**
	 * Gets the value of the x509Certificate property.
	 *
	 * @return
	 *     possible object is
	 *     byte[]
	 */
	public byte[] getX509Certificate() {
		return x509Certificate;
	}

	/**
	 * Sets the value of the x509Certificate property.
	 *
	 * @param value
	 *     allowed object is
	 *     byte[]
	 */
	public void setX509Certificate(byte[] value) {
		this.x509Certificate = value;
	}

}
