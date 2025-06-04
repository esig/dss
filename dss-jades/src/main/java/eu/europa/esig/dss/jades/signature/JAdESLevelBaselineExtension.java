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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.enumerations.SigningOperation;

/**
 * JAdES extension
 *
 */
public interface JAdESLevelBaselineExtension extends SignatureExtension<JAdESSignatureParameters> {

    /**
     * Sets the signing operation
     *
     * NOTE: the internal variable, used in the signature creation/extension process
     *
     * @param signingOperation {@link SigningOperation}
     */
    void setOperationKind(SigningOperation signingOperation);

}
