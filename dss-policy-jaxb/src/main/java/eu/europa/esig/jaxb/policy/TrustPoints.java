package eu.europa.esig.jaxb.policy;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>Java class for TrustPoints complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;element name="TrustPoints" minOccurs="0">
 *   &lt;complexType>
 *     &lt;sequence>
 *       &lt;element name="X509Certificate" type="{http://www.w3.org/2001/XMLSchema}base64Binary" maxOccurs="unbounded" minOccurs="0"/>
 *     &lt;/sequence>
 *   &lt;/complexType>
 * &lt;/element>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TrustPoints", propOrder = {
   "X509Certificate"
})
public class TrustPoints {

    @XmlElement(name = "X509Certificate")
	protected List<byte[]> x509Certificate;

	public List<byte[]> getX509Certificate() {
		if (x509Certificate == null) {
			x509Certificate = new ArrayList<byte[]>();
		}
		return x509Certificate;
	}

	public void setX509Certificate(List<byte[]> x509Certificate) {
		this.x509Certificate = x509Certificate;
	}

}
