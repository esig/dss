/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS2513Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/belgian_pki_multiple_ocsps.pdf"));
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);

        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        String ocspToLoadBase64 = "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";
        ExternalResourcesOCSPSource ocspSource = new ExternalResourcesOCSPSource(new InMemoryDocument(Utils.fromBase64(ocspToLoadBase64)));
        certificateVerifier.setOcspSource(ocspSource);

        final Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calendar.set(2021, 6, 15, 9, 14, 40);
        validator.setValidationTime(calendar.getTime());

        validator.setCertificateVerifier(certificateVerifier);
        return validator;
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIFjjCCA3agAwIBAgIITzMgjMWUvzgwDQYJKoZIhvcNAQELBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTQwHhcNMTMwNjI2MTIwMDAwWhcNMzIxMDIyMTIwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJiQrvrHHm+O4AU6syN4TNHWL911PFsY6E9euwVml5NAWTdw9p2mcmEOYGx424jFLpSQVNxxxoh3LsIpdWUMRQfuiDqzvZx/4dCBaeKL/AMRJuL1d6wU73XKSkdDr5uH6H2Yf19zSiUOm2x4k3aNLyT+VryF11b1Prp67CBk63OBmG0WUaB+ExtBHOkfPaHRHFA04MigoVFt3gLQRGh1V+H1rm1hydTzd6zzpoJHp3ujWD4r4kLCrxVFV0QZ44usvAPlhKoecF0feiKtegS1pS+FjGHA9S85yxZknEV8N6bbK5YP7kgNLDDCNFJ6G7MMpf8MEygXWMb+WrynTetWnIV6jTzZA1RmaZuqmIMDvWTA7JNkiDJQOJBWQ3Ehp+Vn7li1MCIjXlEDYJ2wRmcRZQ0bsUzaM/V3p+Q+j8S3osma3Pc6+dDzxL+Og/lnRnLlDapXx28XB9urUR5H03Ozm77B9/mYgIeM8Y1XntlCCELBeuJeEYJUqc0FsGxWNwjsBtRoZ4dva1rvzkXmjJuNIR4YILg8G4kKLhr9JDrtyCkvI9Xm8GDjqQIJ2KpQiJHBLJA0gKxlYem8CSO/an3AOxqTNZjWbQx6E32OPB/rsU28ldadi9c8yeRyXLWpUF4Ghjyoc4OdrAkXmljnkzLMC459xGL8gj6LyNb6UzX0eYA9AgMBAAGjgbswgbgwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wQgYDVR0gBDswOTA3BgVgOAwBATAuMCwGCCsGAQUFBwIBFiBodHRwOi8vcmVwb3NpdG9yeS5laWQuYmVsZ2l1bS5iZTAdBgNVHQ4EFgQUZ+jxTk+ztfMHbwicDIPZetlb50kwEQYJYIZIAYb4QgEBBAQDAgAHMB8GA1UdIwQYMBaAFGfo8U5Ps7XzB28InAyD2XrZW+dJMA0GCSqGSIb3DQEBCwUAA4ICAQBe3CQAZrNwVZ9Ll3nFWkaKDvMwOE2s1NysTfocGUwyd6c01qsSN52BhRqpaSEWLeSXAfPQK+f57M1hXLNVE8VMf1Vtc0ge+VgjKOWLJ+4d0CAk8VIAK55NUkrSbu4pn+osfD/He0jfECKyq9xrhbn4yxZ/d5qj8RSj+aPmCoX/kaODZmug+AfzY+TXeJgjn8eEQGO8zDJoV/hdUuotkf8eQXeuRhoCuvipBm7vHqEA946NuVtRUmaztLUR9CkbSZ1plWWmqKC+QKErWzvBeswrWxzaRoW9Un7qCSmiO9ddkEHVRHibkUQvPn8kGdG/uOmmRQsbjFuARNCMWS4nHc6TTw7dJgkeZjZiqPl22ifsWJsR/w/VuJMA4kSot/h6qQV9Eglo4ClRlEk3yzbKkcJkLKk6lA90/u46KsqSC5MgUeFjER398iXqpDpT8BzIMovMzHlK7pxTJA5cWXN2a8OMhYCA/Kb6dqIXIi8NKsqzVMXJfX65DM2gWA8rjicJWoooqLhUKuZ6tSWA6If2TRr7MfQsVDhwwUk6mvEIaBJBcyOWH8XgyY6uuHuvGe8CkK+Yk4X2TiE+7GuQe4YVJ/MOGdS3V1eZwPmWSu++azOOFrwoZpIPKOwjbsuLbs0xt6BwWW2XFP025BDh/OD6UE4VsyznnUCkb4AbS947UX6NGA=="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIFvDCCBKSgAwIBAgIQKHqaSkfMcieN0Hwf0Uz4rzANBgkqhkiG9w0BAQsFADB2MQswCQYDVQQGEwJGUjEgMB4GA1UEChMXQ3J5cHRvbG9nIEludGVybmF0aW9uYWwxHDAaBgNVBAsTEzAwMDIgNDM5MTI5MTY0MDAwMjYxJzAlBgNVBAMTHlVuaXZlcnNpZ24gUHJpbWFyeSBDQSBoYXJkd2FyZTAeFw0xOTEwMTQxMDAxMzdaFw0zOTEwMTQxMDAxMzdaMG4xCzAJBgNVBAYTAkZSMSAwHgYDVQQKExdDcnlwdG9sb2cgSW50ZXJuYXRpb25hbDEYMBYGA1UEYRMPTlRSRlItNDM5MTI5MTY0MSMwIQYDVQQDExpVbml2ZXJzaWduIFRpbWVzdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMFtohA2jGml4x8KBP8xGT2cJne86/zfeQFslwqRj+ir+TDwhTLTNMEy/g79/vAejoW9J/9NTH63FMPtWWmFhTwP9+1qEYBjyxorH2RhcEHOzkjW+ehc3XDjmnk95QvItxS5JMO9DVY1+0lbMvzbc1Gt+L8FGTmjDmx3eTIkmjvzQ16NmXgYoZ4BkMFWsR7RUr1t2u9gIESFK7RVZKo/eWJ3GV5qcL9C4sFp3f/vog1MruV9FLmtDPr/qVVFjW15kCEgCoJHwNHRs7AwlWONEpQLp8ERV/1uPN82tSo3W7I2u+Frh/AJGJsQQ440rGT7xuO7VCMbJn9w8407wIbJHQujGZrd3ZmSz5cmHGjoZFsO3XFK8Z9yRVwy0aDu2BxGqoyUgVQwPvjUaKCkYMWoE6Pj1yOTlS2Z3KRQyPTA+YUnhFbBPukOBDT3b2ldpvRipb+TkGM53h6g39LeKo+8Q7UuGpW8Ro/0TlJexjvY6/La7ygh47/zW8vBH3wr9XIDcrA1bez+NCA/J4MNafgFGaA0EcCUv/iMW9syZ5qCX7vEbSzlRyQbqjhXg3ncsncUXotH6szTnbMUpNwGm0X/ifHZKLEPTWthPpOT7oduyGh3I5vSKYkb0v76BmWmYGeWywdXPIg+NiB7CykUCyqIe1FGqIUVf09ZLZC5pwVjwpidAgMBAAGjggFMMIIBSDAOBgNVHQ8BAf8EBAMCAQYwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC51bml2ZXJzaWduLmV1L3VuaXZlcnNpZ25fcHJpbWFyeV9jYV9oYXJkd2FyZS5jcmwwHQYDVR0OBBYEFBlOgh6gQar8AZusd+6Hv+AKqCb9MDsGA1UdIAQ0MDIwMAYEVR0gADAoMCYGCCsGAQUFBwIBFhpodHRwOi8vZG9jcy51bml2ZXJzaWduLmV1LzASBgNVHRMBAf8ECDAGAQH/AgEAMFcGCCsGAQUFBwEBBEswSTBHBggrBgEFBQcwAoY7aHR0cHM6Ly93d3cudW5pdmVyc2lnbi5jb20vZG9jdW1lbnRzL3VuaXZlcnNpZ24tcm9vdC1jYS5jcnQwHwYDVR0jBBgwFoAUTdn8qC3HyFqkrV9Jrmik3J6KEiIwDQYJKoZIhvcNAQELBQADggEBAEFr28zJPEO/2Q5lqdkXuXwj32nRdoEivOjLXPSQLTsa/ee5EzZ1CnQjLcvkqSEldEUWaoXE/HMoFPS1goMnIqQa6+rnEfQ6qmvVLPt/j79FCVWpeUyjWtfRfKH8firFbKfm0ngtA2Mfb/U09nHbgtXSzFAks6zU1RxlwEgaOGex+TjwHcVp0DD+okSDtjNXi3F4DjzVQ4q/v1GN3HT2HwaJtWGvDjw/glmc3xC+eCpJKbBI6SbjmO2C/fuB1q1AL2e87wMKwQ+Z1NTbJLVU4UIwCzAXtCWU2lj2A++OdJMrGNXvxoGQW94LbQijqEPqXMkeDnQBgv1FSmV16oloy7U="));
        return trustedCertificateSource;
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
        assertEquals(1, certificateRevocationData.size());

        boolean externalOCSPFound = false;
        for (CertificateRevocationWrapper revocationWrapper  :certificateRevocationData) {
            if (RevocationOrigin.EXTERNAL.equals(revocationWrapper.getOrigin())) {
                externalOCSPFound = true;
                break;
            }
        }
        assertFalse(externalOCSPFound);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        for (TimestampWrapper timestampWrapper : timestampList) {
            if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
                List<String> timestampedCertificateIds = timestampWrapper.getTimestampedCertificates()
                        .stream().map(c -> c.getId()).collect(Collectors.toList());
                for (RevocationWrapper revocationWrapper : timestampWrapper.getTimestampedRevocations()) {
                    for (CertificateWrapper certificateWrapper : revocationWrapper.foundCertificates().getRelatedCertificates()) {
                        assertTrue(timestampedCertificateIds.contains(certificateWrapper.getId()));
                    }
                }
            }
        }
    }

}
