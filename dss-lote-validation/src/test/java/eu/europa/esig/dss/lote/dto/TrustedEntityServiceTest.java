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
package eu.europa.esig.dss.lote.dto;

import eu.europa.esig.dss.model.lote.ServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.lote.TrustedEntityService;
import eu.europa.esig.dss.model.lote.TrustedEntityServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class TrustedEntityServiceTest {

    private static CertificateToken cert;

    @BeforeAll
    static void init() {
        cert = DSSUtils.loadCertificateFromBase64EncodedString("MIIFdjCCA96gAwIBAgICBFcwDQYJKoZIhvcNAQELBQAwWjESMBAGA1UEAwwJRUFBUSBDZXJ0MSQwIgYDVQQKDBtRRUFBIFRydXN0IFNlcnZpY2UgUHJvdmlkZXIxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJFVTAeFw0yNTAyMTAxMDA1MjhaFw0yNzAyMTAxMDA1MjhaMFsxEzARBgNVBAMMCkFsaWNlIENlcnQxJDAiBgNVBAoMG1FFQUEgVHJ1c3QgU2VydmljZSBQcm92aWRlcjERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkVVMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAwvlryjNGJQY1m4T0XXVCdDOOgUOOx01vb2F4S+4Kc7p+XYAK5rYzr2l386EwwBxT3kJg5WHIDWLFxJdPCF3v1WR0s/9zYLDKyu71mPjMEXOPcK3qVnAEYfzdAq7pve40T9XGe+A3h99BePhL/VLKM4bITuSAprWkOlxU4IIFXBhlrL5NhASnGrVx/EHmVqUym3/lCCS6Nb9OrVdFkfAD1k/KjmY4Oe6O8dTEmsxvdZJkW4MVziKWsuulqJVLgiydvrkfLeq/MF5U6r6N5N8zEUx3qUF/nmAETldDZUVY3PMstfn7GuiUnzTQMgpkbYIDMcJLmoChdMRiNKhMLbf8k2O7Q/R2crnbxnmtrLmoNXCJ4vRgTXSxdIkdoPRgpnT/l/brLmUP+67c7+s3Dg+aCOappxIvtwXyGaUKjoD5yjOvVGfUy5bWR/26gobJ0C4CG04UkxWhZDhoe5vzYQcMJfFV0VgoHIl3OFBEjkaD6muent191Zn3EfdW5esjPlDLAgMBAAGjggFDMIIBPzAOBgNVHQ8BAf8EBAMCBsAwNwYIKwYBBQUHAQMEKzApMAgGBgQAjkYBATAIBgYEAI5GAQQwEwYGBACORgEGMAkGBwQAjkYBBgEwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2xvY2FsaG9zdDo5OTk5L3BraS1mYWN0b3J5L2NybC9FQUFRIENlcnQuY3JsMIGOBggrBgEFBQcBAQSBgTB/MDwGCCsGAQUFBzABhjBodHRwOi8vbG9jYWxob3N0Ojk5OTkvcGtpLWZhY3Rvcnkvb2NzcC9FQUFRIENlcnQwPwYIKwYBBQUHMAKGM2h0dHA6Ly9sb2NhbGhvc3Q6OTk5OS9wa2ktZmFjdG9yeS9jcnQvRUFBUSBDZXJ0LmNydDAdBgNVHQ4EFgQUexbMei5Jf0Nckwe9jkJeBYSA86owDQYJKoZIhvcNAQELBQADggGBAKVJ3WRux33Bks7eWrA+Q/Av/DWh4n/U1Uiem7qebW4M/Jbjfpw4gLc788D9Q7ENYL/ae25a+JrDew7XqMTZiAGOqPCZ6mP7qvJn62ROEYgzO9oBgS3ArH8bg+LmuYMTb73VdJMIQB/8mcTceEAvvUz5NMwiYWagHJQ7wMrQmN3ZGdVQ7pQ3wU9MuBzRrij6IN6r7S3TBSAHaDqqKBaK9Mvjt5kIsDdGzp88hhrNaQbdeU1fvE0sNNZfMf1JlgdTotJooGBTzeIFVIaNKpwW4X6dpYfRygJQC+Bokwg9FTwUKwgBbTZcTOZQ9kzQsyw0vEC4l6JCh97sq6NneE55ALq2z9Z1u08unM9bviTIKDNPn0GbwIjGzCEiQpETHQQ/SJTr7+jnH2kibPxvwu4I7K5PBIEcnDhAIvQ5DHl99R9YkSvTYOZQfHlGIySoiNMGWfzsR9TF9qg/42eUpcyrsCaQxiNZ+IwYse4/ZWIwg6LHnigSuDGnbY5GNGx2SX1Gcw==");
    }

    @Test
    void test() {
        List<CertificateToken> certificates = Collections.singletonList(cert);

        TrustedEntityServiceStatusAndInformationExtensions serviceStatus =
                new TrustedEntityServiceStatusAndInformationExtensions.ServiceStatusAndInformationExtensionsBuilder()
                        .setNames(Collections.singletonMap("en", Collections.singletonList("PID Provider Trusted Entity")))
                        .setType("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList")
                        .setStatus("http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU")
                        .setServiceSupplyPoints(Collections.singletonList("https://pid.example.eu/pid-providers"))
                        .setStartDate(new Date(1704067200000L))
                        .build();

        TimeDependentValues<ServiceStatusAndInformationExtensions> status =
                new TimeDependentValues<ServiceStatusAndInformationExtensions>(
                        Collections.<ServiceStatusAndInformationExtensions>singletonList(serviceStatus));

        TrustedEntityService service = new TrustedEntityService.TrustEntityServiceBuilder()
                .setCertificates(certificates)
                .setStatusAndInformationExtensions(status)
                .build();

        assertEquals(certificates, service.getCertificates());
        assertEquals(status, service.getStatusAndInformationExtensions());

        assertEquals(serviceStatus, service.getStatusAndInformationExtensions().getLatest());
    }

    @Test
    void trustedEntityNullTest() {
        TrustedEntityService service = new TrustedEntityService.TrustEntityServiceBuilder()
                .build();

        assertNull(service.getCertificates());
        assertNull(service.getStatusAndInformationExtensions());
    }

}
