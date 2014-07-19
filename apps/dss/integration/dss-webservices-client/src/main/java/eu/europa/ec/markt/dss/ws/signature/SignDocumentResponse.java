
package eu.europa.ec.markt.dss.ws.signature;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for signDocumentResponse complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="signDocumentResponse">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="response" type="{http://ws.dss.markt.ec.europa.eu/}wsDocument" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "signDocumentResponse", propOrder = {
    "response"
})
public class SignDocumentResponse {

    protected WsDocument response;

    /**
     * Gets the value of the response property.
     * 
     * @return
     *     possible object is
     *     {@link WsDocument }
     *     
     */
    public WsDocument getResponse() {
        return response;
    }

    /**
     * Sets the value of the response property.
     * 
     * @param value
     *     allowed object is
     *     {@link WsDocument }
     *     
     */
    public void setResponse(WsDocument value) {
        this.response = value;
    }

}
