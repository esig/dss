package eu.europa.esig.jaxb.policy;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for MultiValuesConstraint complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CACertificateConstraints">
 *   &lt;complexContent>
 *     &lt;extension base="{http://dss.esig.europa.eu/validation/policy}CertificateConstraints">
 *       &lt;sequence>
 *         &lt;element name="TrustPoints" type="{http://www.w3.org/2001/XMLSchema}base64Binary" maxOccurs="unbounded" minOccurs="0"/>
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
    protected List<byte[]> trustPoints;

    /**
     * Gets the value of the X509Certificate bytes from the trust anchor CAs (according to ETSI TS 102 853, item 5.3.4).
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
	public List<byte[]> getTrustPoints() {
        if (trustPoints == null) {
        	trustPoints = new ArrayList<byte[]>();
        }
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
	public void setTrustPoints(List<byte[]> trustPoints) {
		this.trustPoints = trustPoints;
	}
}
