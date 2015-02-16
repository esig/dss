
package eu.europa.ec.markt.dss.ws.signature;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for extendSignature complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="extendSignature">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="signedDocument" type="{http://ws.dss.markt.ec.europa.eu/}wsDocument" minOccurs="0"/>
 *         &lt;element name="wsParameters" type="{http://ws.dss.markt.ec.europa.eu/}wsParameters" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "extendSignature", propOrder = {
    "signedDocument",
    "wsParameters"
})
public class ExtendSignature {

    protected WsDocument signedDocument;
    protected WsParameters wsParameters;

    /**
     * Gets the value of the signedDocument property.
     * 
     * @return
     *     possible object is
     *     {@link WsDocument }
     *     
     */
    public WsDocument getSignedDocument() {
        return signedDocument;
    }

    /**
     * Sets the value of the signedDocument property.
     * 
     * @param value
     *     allowed object is
     *     {@link WsDocument }
     *     
     */
    public void setSignedDocument(WsDocument value) {
        this.signedDocument = value;
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

}
