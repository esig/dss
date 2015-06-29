
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
package eu.europa.esig.dss.wsclient.validation;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 *
 * 
 *
 * 
 * <pre>
 * &lt;complexType name="validateDocument">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="document" type="{http://ws.dss.esig.europa.eu/}wsDocument" minOccurs="0"/>
 *         &lt;element name="detachedContent" type="{http://ws.dss.esig.europa.eu/}wsDocument" minOccurs="0"/>
 *         &lt;element name="policy" type="{http://ws.dss.esig.europa.eu/}wsDocument" minOccurs="0"/>
 *         &lt;element name="diagnosticDataToBeReturned" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "validateDocument", propOrder = {
    "document",
    "detachedContent",
    "policy",
    "diagnosticDataToBeReturned"
})
public class ValidateDocument {

    protected WsDocument document;
    protected WsDocument detachedContent;
    protected WsDocument policy;
    protected boolean diagnosticDataToBeReturned;

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
     * Gets the value of the detachedContent property.
     * 
     * @return
     *     possible object is
     *     {@link WsDocument }
     *     
     */
    public WsDocument getDetachedContent() {
        return detachedContent;
    }

    /**
     * Sets the value of the detachedContent property.
     * 
     * @param value
     *     allowed object is
     *     {@link WsDocument }
     *     
     */
    public void setDetachedContent(WsDocument value) {
        this.detachedContent = value;
    }

    /**
     * Gets the value of the policy property.
     * 
     * @return
     *     possible object is
     *     {@link WsDocument }
     *     
     */
    public WsDocument getPolicy() {
        return policy;
    }

    /**
     * Sets the value of the policy property.
     * 
     * @param value
     *     allowed object is
     *     {@link WsDocument }
     *     
     */
    public void setPolicy(WsDocument value) {
        this.policy = value;
    }

    /**
     * Gets the value of the diagnosticDataToBeReturned property.
     * 
     */
    public boolean isDiagnosticDataToBeReturned() {
        return diagnosticDataToBeReturned;
    }

    /**
     * Sets the value of the diagnosticDataToBeReturned property.
     * 
     */
    public void setDiagnosticDataToBeReturned(boolean value) {
        this.diagnosticDataToBeReturned = value;
    }

}
