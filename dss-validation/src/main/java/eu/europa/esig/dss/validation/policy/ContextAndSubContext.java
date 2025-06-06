/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
