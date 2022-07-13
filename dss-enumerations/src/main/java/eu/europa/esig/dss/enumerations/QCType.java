package eu.europa.esig.dss.enumerations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Defines QC Type OID identifiers
 */
public interface QCType extends OidDescription {

    Logger LOG = LoggerFactory.getLogger(QCType.class);

    /** Defines a description for a type unknown by the current implementation */
    String UNKNOWN_TYPE = "type-unknown";

    /**
     * Returns a {@code QCType} by the given OID, if exists
     *
     * @param oid {@link String} to get {@link QCType} for
     * @return {@link QCType} if exists, NULL otherwise
     */
    static QCType fromOid(String oid) {
        for (QCType type : QCTypeEnum.values()) {
            if (type.getOid().equals(oid)) {
                return type;
            }
        }

        LOG.debug("Not supported QcType : '{}'", oid);
        return new QCType() {
            @Override
            public String getDescription() { return UNKNOWN_TYPE; }
            @Override
            public String getOid() { return oid; }
        };
    }

}
