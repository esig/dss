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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.pseudo;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a merged strategy to extract pseudo information, accepting the certificate's pseudo attribute and
 * custom German pseudo processing algorithm
 *
 */
public class JoinedPseudoStrategy implements PseudoStrategy {

    /** List of strategies to be used to extract pseudo */
    private static final List<PseudoStrategy> STRATEGIES;

    static {
        STRATEGIES = new ArrayList<>();
        STRATEGIES.add(new PseudoAttributeStrategy());
        STRATEGIES.add(new PseudoGermanyStrategy());
    }

    /**
     * Default constructor
     */
    public JoinedPseudoStrategy() {
        // empty
    }

    @Override
    public String getPseudo(CertificateWrapper certificate) {
        for (PseudoStrategy strategy : STRATEGIES) {
            String pseudo = strategy.getPseudo(certificate);
            if (Utils.isStringNotEmpty(pseudo)) {
                return pseudo;
            }
        }
        return null;
    }

}
