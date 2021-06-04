package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.enumerations.RevocationType;

/**
 * Wrapper class for XML orphan revocation data
 *
 */
public class OrphanRevocationTokenWrapper extends OrphanTokenWrapper<XmlOrphanRevocationToken> {

    /**
     * Default constructor
     *
     * @param orphanToken {@link XmlOrphanRevocationToken}
     */
    protected OrphanRevocationTokenWrapper(XmlOrphanRevocationToken orphanToken) {
        super(orphanToken);
    }

    /**
     * Returns a revocation data type (CRL or OCSP)
     *
     * @return {@link RevocationType}
     */
    public RevocationType getRevocationType() {
        return orphanToken.getRevocationType();
    }

    @Override
    public byte[] getBinaries() {
        return orphanToken.getBase64Encoded();
    }

    @Override
    public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
        return orphanToken.getDigestAlgoAndValue();
    }

}
