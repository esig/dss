package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.attestation.common.creation.claim.AttestationClaimObject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Represents a CBOR object to be incorporated as an ISO/IEC mdoc claim
 *
 */
public class MdocClaimObject extends MdocClaim implements AttestationClaimObject<MdocClaim> {

    private static final long serialVersionUID = 3168092769419251983L;

    /**
     * Create a {@link MdocClaimObject}. The name of the claim will be null.
     *
     * @return the created {@link MdocClaimObject}
     */
    public static MdocClaimObject create() {
        return new MdocClaimObject(new ArrayList<>());
    }

    /**
     * Create a {@link MdocClaimObject} with the provided name
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link MdocClaimObject}
     */
    public static MdocClaimObject create(final String name) {
        return new MdocClaimObject(name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocClaimObject}.
     * DigestId and salt will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @return the created {@link MdocClaim}
     */
    public static MdocClaimObject create(final String namespace, final String name) {
        return new MdocClaimObject(namespace, name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocClaimObject} with the provided digestId.
     * Salt will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer identifier of the claim digest
     * @param name {@link String} the claim name
     * @return the created {@link MdocClaim}
     */
    public static MdocClaimObject create(final String namespace, final int digestId, final String name) {
        return new MdocClaimObject(namespace, digestId, name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocClaimObject} with the provided salt.
     * DigestId will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     * @return the created {@link MdocClaim}
     */
    public static MdocClaimObject create(final String namespace, final String name, final byte[] salt) {
        return new MdocClaimObject(namespace, name, new ArrayList<>(), salt);
    }

    /**
     * Create a {@link MdocClaimObject} with the provided digestId and salt.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer identifier of the claim digest
     * @param name {@link String} the claim name
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     * @return the created {@link MdocClaim}
     */
    public static MdocClaimObject create(final String namespace, final int digestId, final String name, final byte[] salt) {
        return new MdocClaimObject(namespace, digestId, name, new ArrayList<>(), salt);
    }

    /**
     * Constructor with the value
     *
     * @param children a list of embedded {@code MdocClaim} in the object
     */
    protected MdocClaimObject(List<MdocClaim> children) {
        super(null, children);
    }

    /**
     * Constructor with the claim name and value
     *
     * @param name  {@link String} the claim name
     * @param children a list of embedded {@code MdocClaim} in the object
     */
    protected MdocClaimObject(String name, List<MdocClaim> children) {
        super(null, name, children);
    }

    /**
     * Constructor with the claim namespace, name and value
     *
     * @param namespace {@link String}
     * @param name  {@link String} the claim name
     * @param children a list of embedded {@code MdocClaim} in the object
     */
    protected MdocClaimObject(String namespace, String name, List<MdocClaim> children) {
        super(namespace, name, children);
    }

    /**
     * Constructor with the claim namespace, digestId, name and value
     *
     * @param namespace {@link String}
     * @param digestId integer identifier of the claim digest
     * @param name  {@link String} the claim name
     * @param children a list of embedded {@code MdocClaim} in the object
     */
    protected MdocClaimObject(String namespace, int digestId, String name, List<MdocClaim> children) {
        super(namespace, digestId, name, children);
    }

    /**
     * Constructor with the claim namespace, name, value and salt
     *
     * @param namespace {@link String}
     * @param name  {@link String} the claim name
     * @param children a list of embedded {@code MdocClaim} in the object
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     */
    protected MdocClaimObject(String namespace, String name, List<MdocClaim> children, byte[] salt) {
        super(namespace, name, children, salt);
    }

    /**
     * Constructor with the claim namespace, digestId, name, value and salt
     *
     * @param namespace {@link String}
     * @param digestId integer identifier of the claim digest
     * @param name  {@link String} the claim name
     * @param children a list of embedded {@code MdocClaim} in the object
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     */
    protected MdocClaimObject(String namespace, int digestId, String name, List<MdocClaim> children, byte[] salt) {
        super(namespace, digestId, name, children, salt);
    }

    @Override
    public void addChild(final MdocClaim child) {
        getChildren().add(child);
    }

    /**
     * Adds a collection of children to the object
     *
     * @param children a collection of {@link MdocClaim}
     */
    public void addChildren(final Collection<MdocClaim> children) {
        getChildren().addAll(children);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<MdocClaim> getChildren() {
        return (List<MdocClaim>) getValue();
    }

    @Override
    public CBORObject getValueAsCbor() {
        final CBORMap cborMap = new CBORMap();
        for (MdocClaim child : getChildren()) {
            cborMap.put(child.getName(), child.getValueAsCbor());
        }
        return cborMap;
    }

}
