package eu.europa.esig.dss.model;

import java.io.Serializable;

/**
 * This class is used to define a CommitmentTypeQualifier to be incorporated within a signature
 *
 */
public class CommitmentQualifier implements Serializable {

    private static final long serialVersionUID = -1291715111587521496L;

    /** Defines unique commitment qualifier identifier (CAdES/PAdES only) */
    private String oid;

    /** Defines the content of the qualifier (required) */
    private DSSDocument content;

    /**
     * Default constructor instantiating object with null values
     */
    public CommitmentQualifier() {
    }

    /**
     * Gets unique object identifier of the Commitment Qualifier
     *
     * @return {@link String}
     */
    public String getOid() {
        return oid;
    }

    /**
     * Sets unique object identifier of the Commitment Qualifier (CAdES/PAdES only!)
     *
     * Use : CONDITIONAL (required for CAdES/PAdES)
     *
     * @param oid {@link String}
     */
    public void setOid(String oid) {
        this.oid = oid;
    }

    /**
     * Gets the content of the Commitment Qualifier
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getContent() {
        return content;
    }

    /**
     * Sets the content of Commitment Qualifier.
     *
     * The content of a qualifier may be anytype, but developers may need to ensure
     * the content corresponds to the used signature format (i.e. XML for XAdES, ASN.1 for CAdES, etc.).
     *
     * Use : REQUIRED
     *
     * @param content {@link DSSDocument}
     */
    public void setContent(DSSDocument content) {
        this.content = content;
    }

}
