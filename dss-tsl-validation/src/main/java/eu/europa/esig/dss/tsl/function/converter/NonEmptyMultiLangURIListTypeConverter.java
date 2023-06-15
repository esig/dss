package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * The class is used to extract non-empty URI language based values
 *
 */
public class NonEmptyMultiLangURIListTypeConverter implements Function<NonEmptyMultiLangURIListType, Map<String, List<String>>> {

    /** The predicate to be used */
    private final Predicate<String> predicate;

    /**
     * Default constructor (selects all)
     */
    public NonEmptyMultiLangURIListTypeConverter() {
        // select all
        this(x -> true);
    }

    /**
     * Default constructor with a filter predicate
     *
     * @param predicate {@link Predicate}
     */
    public NonEmptyMultiLangURIListTypeConverter(Predicate<String> predicate) {
        super();
        this.predicate = predicate;
    }

    @Override
    public Map<String, List<String>> apply(NonEmptyMultiLangURIListType original) {
        Map<String, List<String>> result = new HashMap<>();
        if (original != null && Utils.isCollectionNotEmpty(original.getURI())) {
            for (NonEmptyMultiLangURIType multiLangURIString : original.getURI()) {
                final String lang = multiLangURIString.getLang();
                final String value = multiLangURIString.getValue();
                if (predicate.test(value)) {
                    result.computeIfAbsent(lang, k -> new ArrayList<>()).add(value);
                }
            }
        }
        return result;
    }

}
