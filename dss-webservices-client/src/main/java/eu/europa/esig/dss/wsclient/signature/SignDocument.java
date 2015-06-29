
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
 * &lt;complexType name="signDocument">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="document" type="{http://ws.dss.esig.europa.eu/}wsDocument" minOccurs="0"/>
 *         &lt;element name="wsParameters" type="{http://ws.dss.esig.europa.eu/}wsParameters" minOccurs="0"/>
 *         &lt;element name="signatureValue" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "signDocument", propOrder = {
    "document",
    "wsParameters",
    "signatureValue"
})
public class SignDocument {

    protected WsDocument document;
    protected WsParameters wsParameters;
    protected byte[] signatureValue;

    /**
     * Gets the value of the document property.
     * 
     * @return
     *     possible object is
     *     {@link WsDocument }
     *     
     */
    public WsDocument getDocument() {
        return document;
    }

    /**
     * Sets the value of the document property.
     * 
     * @param value
     *     allowed object is
     *     {@link WsDocument }
     *     
     */
    public void setDocument(WsDocument value) {
        this.document = value;
    }

    /**
     * Gets the value of the wsParameters property.
     * 
     * @return
     *     possible object is
     *     {@link WsParameters }
     *     
     */
    public WsParameters getWsParameters() {
        return wsParameters;
    }

    /**
     * Sets the value of the wsParameters property.
     * 
     * @param value
     *     allowed object is
     *     {@link WsParameters }
     *     
     */
    public void setWsParameters(WsParameters value) {
        this.wsParameters = value;
    }

    /**
     * Gets the value of the signatureValue property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getSignatureValue() {
        return signatureValue;
    }

    /**
     * Sets the value of the signatureValue property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setSignatureValue(byte[] value) {
        this.signatureValue = value;
    }

}
