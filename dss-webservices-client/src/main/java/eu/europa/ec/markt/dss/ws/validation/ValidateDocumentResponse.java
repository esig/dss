
package eu.europa.ec.markt.dss.ws.validation;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for validateDocumentResponse complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="validateDocumentResponse">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="response" type="{http://ws.dss.markt.ec.europa.eu/}wsValidationReport" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "validateDocumentResponse", propOrder = {
    "response"
})
public class ValidateDocumentResponse {

    protected WsValidationReport response;

    /**
     * Gets the value of the response property.
     * 
     * @return
     *     possible object is
     *     {@link WsValidationReport }
     *     
     */
    public WsValidationReport getResponse() {
        return response;
    }

    /**
     * Sets the value of the response property.
     * 
     * @param value
     *     allowed object is
     *     {@link WsValidationReport }
     *     
     */
    public void setResponse(WsValidationReport value) {
        this.response = value;
    }

}
