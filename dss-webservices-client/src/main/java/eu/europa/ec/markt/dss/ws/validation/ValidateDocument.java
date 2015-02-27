
package eu.europa.ec.markt.dss.ws.validation;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for validateDocument complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="validateDocument">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="document" type="{http://ws.dss.markt.ec.europa.eu/}wsDocument" minOccurs="0"/>
 *         &lt;element name="detachedContent" type="{http://ws.dss.markt.ec.europa.eu/}wsDocument" minOccurs="0"/>
 *         &lt;element name="policy" type="{http://ws.dss.markt.ec.europa.eu/}wsDocument" minOccurs="0"/>
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
