package eu.europa.esig.dss.pki.wrapper;


import java.util.Collection;
import java.util.Map;


public abstract class CollectionUtils {
    static final float DEFAULT_LOAD_FACTOR = 0.75F;

    public CollectionUtils() {
    }

    public static boolean isEmpty(Collection<?> collection) {
        return collection == null || collection.isEmpty();
    }

    public static boolean isEmpty(Map<?, ?> map) {
        return map == null || map.isEmpty();
    }

}
