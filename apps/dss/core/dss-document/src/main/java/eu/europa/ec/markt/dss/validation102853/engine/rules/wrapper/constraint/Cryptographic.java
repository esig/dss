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
public class Cryptographic {

    @XmlElement(name = "AlgoExpirationDate")
    private AlgoExpirationDateList algoExpirationDateList;

    @XmlElement(name = "MainSignature")
    private CertificateAlgorithms MainSignature;

    @XmlElement(name = "SigningCertificate")
    private SigningCertificate signingCertificate;

    @XmlElement(name = "CACertificate")
    private CertificateAlgorithms caCertificate;

    @XmlElement(name = "TimestampCertificate")
    private CertificateAlgorithms timestampCertificate;

    @XmlElement(name = "OCSPCertificate")
    private CertificateAlgorithms ocspCertificate;

    @XmlElement(name = "CRLCertificate")
    private CertificateAlgorithms crlCertificate;

    public AlgoExpirationDateList getAlgoExpirationDateList() {
        return algoExpirationDateList;
    }

    public void setAlgoExpirationDateList(AlgoExpirationDateList algoExpirationDateList) {
        this.algoExpirationDateList = algoExpirationDateList;
    }

    public CertificateAlgorithms getMainSignature() {
        return MainSignature;
    }

    public void setMainSignature(CertificateAlgorithms MainSignature) {
        this.MainSignature = MainSignature;
    }

    public SigningCertificate getSigningCertificate() {
        return signingCertificate;
    }

    public void setSigningCertificate(SigningCertificate signingCertificate) {
        this.signingCertificate = signingCertificate;
    }

    public CertificateAlgorithms getCaCertificate() {
        return caCertificate;
    }

    public void setCaCertificate(CertificateAlgorithms caCertificate) {
        this.caCertificate = caCertificate;
    }

    public CertificateAlgorithms getTimestampCertificate() {
        return timestampCertificate;
    }

    public void setTimestampCertificate(CertificateAlgorithms timestampCertificate) {
        this.timestampCertificate = timestampCertificate;
    }

    public CertificateAlgorithms getOcspCertificate() {
        return ocspCertificate;
    }

    public void setOcspCertificate(CertificateAlgorithms ocspCertificate) {
        this.ocspCertificate = ocspCertificate;
    }

    public CertificateAlgorithms getCrlCertificate() {
        return crlCertificate;
    }

    public void setCrlCertificate(CertificateAlgorithms crlCertificate) {
        this.crlCertificate = crlCertificate;
    }

    @Override
    public String toString() {
        return "Cryptographic{" +
              "algoExpirationDateList=" + algoExpirationDateList +
              ", MainSignature=" + MainSignature +
              ", signingCertificate=" + signingCertificate +
              ", caCertificate=" + caCertificate +
              ", timestampCertificate=" + timestampCertificate +
              ", ocspCertificate=" + ocspCertificate +
              ", crlCertificate=" + crlCertificate +
              '}';
    }


}
