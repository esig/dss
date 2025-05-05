package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.SubContext;

import java.io.Serializable;
import java.util.Objects;

/**
 * This class represents a pair of a {@code Context} and a {@code SubContext} to define
 * an applicability scope of cryptographic rules
 */
public class ContextAndSubContext implements Serializable {

    private static final long serialVersionUID = -2725090637214858622L;

    /** The context scope */
    private final Context context;

    /** The subContext scope */
    private final SubContext subContext;

    /**
     * Constructor for a global context definition
     */
    protected ContextAndSubContext() {
        this(null, null);
    }

    /**
     * Default constructor
     *
     * @param context {@link Context}
     * @param subContext {@link SubContext}
     */
    protected ContextAndSubContext(final Context context, final SubContext subContext) {
        this.context = context;
        this.subContext = subContext;
    }

    /**
     * Gets {@code Context}
     *
     * @return {@link Context}
     */
    protected Context getContext() {
        return context;
    }

    /**
     * Gets {@code SubContext}
     *
     * @return {@link SubContext}
     */
    protected SubContext getSubContext() {
        return subContext;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ContextAndSubContext that = (ContextAndSubContext) o;
        return context == that.context
                && subContext == that.subContext;
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(context);
        result = 31 * result + Objects.hashCode(subContext);
        return result;
    }

    @Override
    public String toString() {
        return "ContextAndSubContext [" +
                "context=" + context +
                ", subContext=" + subContext +
                ']';
    }

}
