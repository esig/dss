package eu.europa.esig.dss.cbades.cbor;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;

import java.util.Date;

/**
 * Factory to create a {@code eu.europa.ec.digit.cddl4j.cbor.CBORValue} from a value
 *
 */
public class CBORValueFactory {

    /**
     * Default constructor
     */
    private CBORValueFactory() {
        // empty
    }

    /**
     * This method coverts the given object to a CBORValue instance, corresponding to the object's format
     *
     * @param object to be converted
     * @return {@link CBORValue}
     */
    public static CBORValue toCBORValue(Object object) {
        if (object instanceof CBORObject) {
            // TODO : remove condition after DSS 6.6.
            return ((CBORObject) object).toCBORValue();
        } else if (object instanceof Date) {
            return CBORTags.tdate(((Date) object).toInstant());
        }
        return CBOR.value(object);
    }

}
