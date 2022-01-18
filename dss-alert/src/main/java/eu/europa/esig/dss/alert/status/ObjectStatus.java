package eu.europa.esig.dss.alert.status;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Implementation of a {@code Status} interface, containing a list of concerned objects' identifiers and
 * their corresponding errors
 *
 */
public class ObjectStatus extends MessageStatus {

    /** Map of object identifiers concerned by the check and the corresponding error messages */
    private Map<String, String> relatedObjectMap = new HashMap<>();

    /**
     * Adds concerned object identifier and information about the occurred event
     *
     * @param objectId {@link String}
     * @param errorMessage {@link String} message
     */
    public void addRelatedObjectIdentifierAndErrorMessage(String objectId, String errorMessage) {
        relatedObjectMap.put(objectId, errorMessage);
    }

    /**
     * Returns corresponding error message for the object with the given id
     *
     * @param objectId {@link String} id of the object to get caused error message for
     * @return {@link String} error message
     */
    public String getMessageForObjectWithId(String objectId) {
        return relatedObjectMap.get(objectId);
    }

    @Override
    public Collection<String> getRelatedObjectIds() {
        return relatedObjectMap.keySet();
    }

    @Override
    public boolean isEmpty() {
        return super.isEmpty() && (relatedObjectMap == null || relatedObjectMap.isEmpty());
    }

    @Override
    public String getErrorString() {
        return getMessage() + " " + objectMapToString();
    }

    /**
     * Returns a string listing the occurred errors for each concerned object
     *
     * @return {@link String}
     */
    protected String objectMapToString() {
        StringBuilder sb = new StringBuilder();
        if (relatedObjectMap != null && !relatedObjectMap.isEmpty()) {
            sb.append("[");
            Iterator<Map.Entry<String, String>> it = relatedObjectMap.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, String> entry = it.next();
                sb.append(entry.getKey()).append(": ");
                sb.append(entry.getValue());
                if (it.hasNext()) {
                    sb.append("; ");
                }
            }
            sb.append("]");
        }
        return sb.toString();
    }

}
