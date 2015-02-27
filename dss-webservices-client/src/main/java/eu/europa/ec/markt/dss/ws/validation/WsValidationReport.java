
package eu.europa.ec.markt.dss.ws.validation;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for wsValidationReport complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="wsValidationReport">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="xmlDetailedReport" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="xmlDiagnosticData" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="xmlSimpleReport" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "wsValidationReport", propOrder = {
    "xmlDetailedReport",
    "xmlDiagnosticData",
    "xmlSimpleReport"
})
public class WsValidationReport {

    protected String xmlDetailedReport;
    protected String xmlDiagnosticData;
    protected String xmlSimpleReport;

    /**
     * Gets the value of the xmlDetailedReport property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getXmlDetailedReport() {
        return xmlDetailedReport;
    }

    /**
     * Sets the value of the xmlDetailedReport property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setXmlDetailedReport(String value) {
        this.xmlDetailedReport = value;
    }

    /**
     * Gets the value of the xmlDiagnosticData property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getXmlDiagnosticData() {
        return xmlDiagnosticData;
    }

    /**
     * Sets the value of the xmlDiagnosticData property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setXmlDiagnosticData(String value) {
        this.xmlDiagnosticData = value;
    }

    /**
     * Gets the value of the xmlSimpleReport property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getXmlSimpleReport() {
        return xmlSimpleReport;
    }

    /**
     * Sets the value of the xmlSimpleReport property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setXmlSimpleReport(String value) {
        this.xmlSimpleReport = value;
    }

}
