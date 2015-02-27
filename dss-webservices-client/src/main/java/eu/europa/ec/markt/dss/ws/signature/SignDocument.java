
package eu.europa.ec.markt.dss.ws.signature;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for signDocument complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="signDocument">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="document" type="{http://ws.dss.markt.ec.europa.eu/}wsDocument" minOccurs="0"/>
 *         &lt;element name="wsParameters" type="{http://ws.dss.markt.ec.europa.eu/}wsParameters" minOccurs="0"/>
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
