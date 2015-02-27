package eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper;

/**
 * Created by kaczmani on 04/04/2014.
 */
public class XsdElement {
    String propertyName;
    String propertyType;

    public XsdElement() {
    }

    public XsdElement(String propertyName, String propertyType) {
        this.propertyName = propertyName;
        this.propertyType = propertyType;
    }

    public String getPropertyName() {
        return propertyName;
    }

    public void setPropertyName(String propertyName) {
        this.propertyName = propertyName;
    }

    public String getPropertyType() {
        return propertyType;
    }

    public void setPropertyType(String propertyType) {
        this.propertyType = propertyType;
    }
}
