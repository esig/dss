package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;

import java.io.Serializable;

/**
 * Allows creation of custom ds:Object element
 */
public class DSSObject implements Serializable {

    private static final long serialVersionUID = -4680201985310575707L;

    /**
     * Represents a content of the ds:Object element
     * Can be XML or any other format (e.g. base64 encoded)
     */
    private DSSDocument content;

    /**
     * Represents a value for the "Id" attribute
     */
    private String id;

    /**
     * Represents a value for the "MimeType" attribute
     */
    private MimeType mimeType;

    /**
     * Represents a value for the "Encoding" attribute
     */
    private String encodingAlgorithm;

    /**
     * Default constructor
     */
    public DSSObject() {
    }

    /**
     * Gets the content of the ds:Object element to be created
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getContent() {
        return content;
    }

    /**
     * Sets the content of ds:Object element to be created
     * Can be XML or any other format (e.g. base64 encoded)
     *
     * @param content {@link DSSDocument}
     */
    public void setContent(DSSDocument content) {
        this.content = content;
    }

    /**
     * Gets the Id
     *
     * @return {@link String}
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value for the "Id" attribute
     *
     * @param id {@link String}
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Gets the MimeType
     *
     * @return {@link MimeType}
     */
    public MimeType getMimeType() {
        return mimeType;
    }

    /**
     * Sets the value for the "MimeType" attribute
     *
     * @param mimeType {@link MimeType}
     */
    public void setMimeType(MimeType mimeType) {
        this.mimeType = mimeType;
    }

    /**
     * Gets the encoding algorithm
     *
     * @return {@link String}
     */
    public String getEncodingAlgorithm() {
        return encodingAlgorithm;
    }

    /**
     * Sets the value for the "encoding" attribute
     *
     * @param encodingAlgorithm {@link String}
     */
    public void setEncodingAlgorithm(String encodingAlgorithm) {
        this.encodingAlgorithm = encodingAlgorithm;
    }

}
