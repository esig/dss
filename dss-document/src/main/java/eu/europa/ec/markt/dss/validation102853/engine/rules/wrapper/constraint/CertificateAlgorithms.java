/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 *
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
@XmlAccessorType(XmlAccessType.NONE)
public class CertificateAlgorithms {

    @XmlElement(name = "AcceptableEncryptionAlgo")
    private AlgoList acceptableEncryptionAlgo;

    @XmlElement(name = "MiniPublicKeySize")
    private MiniPublicKeySize miniPublicKeySize;

    @XmlElement(name = "AcceptableDigestAlgo")
    private AlgoList acceptableDigestAlgo;

    public AlgoList getAcceptableEncryptionAlgo() {
        return acceptableEncryptionAlgo;
    }

    public void setAcceptableEncryptionAlgo(AlgoList acceptableEncryptionAlgo) {
        this.acceptableEncryptionAlgo = acceptableEncryptionAlgo;
    }

    public MiniPublicKeySize getMiniPublicKeySize() {
        return miniPublicKeySize;
    }

    public void setMiniPublicKeySize(MiniPublicKeySize miniPublicKeySize) {
        this.miniPublicKeySize = miniPublicKeySize;
    }

    public AlgoList getAcceptableDigestAlgo() {
        return acceptableDigestAlgo;
    }

    public void setAcceptableDigestAlgo(AlgoList acceptableDigestAlgo) {
        this.acceptableDigestAlgo = acceptableDigestAlgo;
    }

    @Override
    public String toString() {
        return "CertificateAlgorithms{" +
              "acceptableEncryptionAlgo=" + acceptableEncryptionAlgo +
              ", miniPublicKeySize=" + miniPublicKeySize +
              ", acceptableDigestAlgo=" + acceptableDigestAlgo +
              '}';
    }
}
