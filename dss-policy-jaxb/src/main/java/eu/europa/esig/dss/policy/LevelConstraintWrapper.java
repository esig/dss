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
package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

/**
 * Wraps {@code eu.europa.esig.dss.policy.jaxb.LevelConstraint} into a {@code eu.europa.esig.dss.model.policy.LevelRule}
 *
 */
public class LevelConstraintWrapper implements LevelRule {

    /** The constraint containing the behavior rules for the corresponding check execution */
    protected final LevelConstraint constraint;

    /**
     * Default constructor
     *
     * @param constraint {@link CryptographicConstraint}
     */
    public LevelConstraintWrapper(final LevelConstraint constraint) {
        this.constraint = constraint;
    }

    @Override
    public Level getLevel() {
        if (constraint != null) {
            return constraint.getLevel();
        }
        return null;
    }

    /**
     * Gets the original constraint
     *
     * @return {@link LevelConstraint}
     */
    public LevelConstraint getConstraint() {
        return constraint;
    }

}
