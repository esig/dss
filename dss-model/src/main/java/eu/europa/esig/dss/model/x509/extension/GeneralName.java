package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.GeneralNameType;

import java.io.Serializable;

/**
 * Represents a general name element (see RFC 5280)
 *
 */
public class GeneralName implements Serializable {

    /** Represents the type of the GeneralName */
    private GeneralNameType generalNameType;

    /** String representation of the GeneralName value */
    private String value;

    /**
     * Default constructor
     */
    public GeneralName() {
        // empty
    }

    /**
     * Gets the type of GeneralName
     *
     * @return {@link GeneralNameType}
     */
    public GeneralNameType getGeneralNameType() {
        return generalNameType;
    }

    /**
     * Sets the type of the GeneralName
     *
     * @param generalNameType {@link GeneralNameType}
     */
    public void setGeneralNameType(GeneralNameType generalNameType) {
        this.generalNameType = generalNameType;
    }

    /**
     * Gets the string representation of the GeneralName value
     *
     * @return {@link String}
     */
    public String getValue() {
        return value;
    }

    /**
     * Sets the string representation of the GeneralName value
     *
     * @param value {@link String}
     */
    public void setValue(String value) {
        this.value = value;
    }

}
