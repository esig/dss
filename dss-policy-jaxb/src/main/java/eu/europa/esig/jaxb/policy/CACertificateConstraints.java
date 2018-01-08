package eu.europa.esig.jaxb.policy;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CACertificateConstraints complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CACertificateConstraints">
 *   &lt;complexContent>
 *     &lt;extension base="{http://dss.esig.europa.eu/validation/policy}CertificateConstraints">
 *       &lt;sequence>
 *         &lt;element name="TrustPoints" minOccurs="0">
 *			 &lt;complexType>
 *             &lt;sequence>
 *               &lt;element name="X509Certificate" type="{http://www.w3.org/2001/XMLSchema}base64Binary" maxOccurs="unbounded" minOccurs="0"/>
 *             &lt;/sequence>
 *           &lt;/complexType>
 *         &lt;/element>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CACertificateConstraints", propOrder = {
    "trustPoints"
})
public class CACertificateConstraints extends CertificateConstraints {
	
    @XmlElement(name = "TrustPoints")
    protected TrustPoints trustPoints;

    /**
     * Gets the value of the X509Certificate bytes from the trust anchor CAs (according to ETSI TS 102 853, item 5.3.4).
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
	public TrustPoints getTrustPoints() {
		return trustPoints;
	}

    /**
     * Sets the value of the X509Certificate bytes from the trust anchor CAs.
     * 
     * @param value
     *     allowed object is
     *     {@link LevelConstraint }
     *     
     */
	public void setTrustPoints(TrustPoints trustPoints) {
		this.trustPoints = trustPoints;
	}
}
