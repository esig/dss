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
package eu.europa.esig.dss.attestation.sd.jwt.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTRefImplValidationTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJ4NWMiOiBbIk1JSUMzekNDQW9XZ0F3SUJBZ0lVZjNsb2hUbURNQW1TL1lYL3E0aHFvUnlKQjU0d0NnWUlLb1pJemowRUF3SXdYREVlTUJ3R0ExVUVBd3dWVUVsRUlFbHpjM1ZsY2lCRFFTQXRJRlZVSURBeU1TMHdLd1lEVlFRS0RDUkZWVVJKSUZkaGJHeGxkQ0JTWldabGNtVnVZMlVnU1cxd2JHVnRaVzUwWVhScGIyNHhDekFKQmdOVkJBWVRBbFZVTUI0WERUSTFNRFF4TURFME16YzFNbG9YRFRJMk1EY3dOREUwTXpjMU1Wb3dVakVVTUJJR0ExVUVBd3dMVUVsRUlFUlRJQzBnTURFeExUQXJCZ05WQkFvTUpFVlZSRWtnVjJGc2JHVjBJRkpsWm1WeVpXNWpaU0JKYlhCc1pXMWxiblJoZEdsdmJqRUxNQWtHQTFVRUJoTUNWVlF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVM3V0FBV3FQemUwVXMzejhwYWp5VlBXQlJtclJiQ2k1WDJzOUd2bHliUXl0d1R1bWNabmVqOUJrTGZBZ2xsb1g1dHYrTmdXZkRmZ3QvMDZzKzV0VjRsbzRJQkxUQ0NBU2t3SHdZRFZSMGpCQmd3Rm9BVVlzZVVSeWk5RDZJV0lLZWF3a21VUlBFQjA4Y3dHd1lEVlIwUkJCUXdFb0lRYVhOemRXVnlMbVYxWkdsM0xtUmxkakFXQmdOVkhTVUJBZjhFRERBS0JnZ3JnUUlDQUFBQkFqQkRCZ05WSFI4RVBEQTZNRGlnTnFBMGhqSm9kSFJ3Y3pvdkwzQnlaWEJ5YjJRdWNHdHBMbVYxWkdsM0xtUmxkaTlqY213dmNHbGtYME5CWDFWVVh6QXlMbU55YkRBZEJnTlZIUTRFRmdRVXFsL29weGtRbFl5MGxsYVRvUGJERS9teUVjRXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1GMEdBMVVkRWdSV01GU0dVbWgwZEhCek9pOHZaMmwwYUhWaUxtTnZiUzlsZFMxa2FXZHBkR0ZzTFdsa1pXNTBhWFI1TFhkaGJHeGxkQzloY21Ob2FYUmxZM1IxY21VdFlXNWtMWEpsWm1WeVpXNWpaUzFtY21GdFpYZHZjbXN3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQU5KVlNEc3FUM0lrR2NLV1dnU2V1YmtET2RpNS9VRTliMUdGL1g1ZlFSRmFBaUJwNXQ2dEhoOFh3RmhQc3R6T0hNb3B2QkQvR3dtczBSQVVnbVNuNmt1OEdnPT0iXX0.eyJfc2QiOiBbIjhoSkRvRFJ4dlUzOFB0YmcyQW9HV0lFYV9nQ0UyT1UzOEJtUUhXRktGYUkiLCAiRnd1TnEzTVdGVnpLSE9iN1BsSlRKa1NGaUxOSy1IZ1UwUkF0RGc3emUzZyIsICJJQTl0N0lsVjlXUG00eW9DdmpGVGFZVDNncGdSXzN4VlNGQ1FGOGxLOWM4IiwgIktKa00xb2JHSHgyX2xYWmUtNnBSOG9KSzZIRlJrdkVnSnU1TjhkYXNEUWsiLCAiV3NsUUNBY0R1QTRPaG0zeUFJNmcydzZ0WlBaRUphdjZvMktrb0NTOHVwayIsICJYU0FVRllrN0I0bWF0SE9oNVp2Yk42YVk3TlJpUFpybDRwVXZfYmU1VU1BIiwgIlhlbjZFLXJTZGFMQkh1M01oem85VjlTYXhvWkl6cFJtM0VCeElGaVpPUE0iLCAiWVNTVHlJYnZGZUdJVS1yZEVKMzZhVGNiV0RuZlZyd1UzbFpJNDFFOWZ4NCIsICJxeHByTHFEM3VIT0RqM2t1dERDQ1RYbjdPeXZPOE5kbkx4ZmNOUzIyWTdrIl0sICJpc3MiOiAiaHR0cHM6Ly9iYWNrZW5kLmlzc3Vlci5ldWRpdy5kZXYiLCAiaWF0IjogMTc3MDUwODgwMCwgImV4cCI6IDE3NzgyODEyMDAsICJ2Y3QiOiAidXJuOmV1ZGk6cGlkOjEiLCAic3RhdHVzIjogeyJpZGVudGlmaWVyX2xpc3QiOiB7ImlkIjogIjEzNTUiLCAidXJpIjogImh0dHBzOi8vaXNzdWVyLmV1ZGl3LmRldi9pZGVudGlmaWVyX2xpc3QvRkMvdXJuOmV1ZGk6cGlkOjEvYWI3MDVmZDYtYjljMi00ODAwLThlMTItZTkyNjkxNmNhZmI4In0sICJzdGF0dXNfbGlzdCI6IHsiaWR4IjogMTM1NSwgInVyaSI6ICJodHRwczovL2lzc3Vlci5ldWRpdy5kZXYvdG9rZW5fc3RhdHVzX2xpc3QvRkMvdXJuOmV1ZGk6cGlkOjEvYWI3MDVmZDYtYjljMi00ODAwLThlMTItZTkyNjkxNmNhZmI4In19LCAiX3NkX2FsZyI6ICJzaGEtMjU2IiwgImNuZiI6IHsiandrIjogeyJrdHkiOiAiRUMiLCAiY3J2IjogIlAtMjU2IiwgIngiOiAibDNBTmZIYTJzT1BmTk12NEJIWmNjWjdHZXVxam1BNzZhbXFMZG4yY190MCIsICJ5IjogInN0VEh1akgtTGgzUUE1OF9hMGhXS3gxakpYckN1OW1PNXBabk1kUDRadVUifX19.J3y36LLW50DKoyKgqURrnaqmG8OAtX0oLg5hrmK87KD_lzCp9_p46w85VdMHKBFI-B9OAH-Q5QKwu9sIeZWBfg~WyJIUjhNRWVHLV9IbExINm5KWEdqYUl3IiwgImJpcnRoZGF0ZSIsICIxOTg4LTA5LTEwIl0~WyJJUE5PWkdsRm9NN0k0WTY0eUhwWWNRIiwgImdpdmVuX25hbWUiLCAiRWxpbyJd~WyJkYzROdkZkai1iUDJkZW5Mb1RodlhnIiwgImZhbWlseV9uYW1lIiwgIkdvZXR0ZWxtYW5uIl0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiMUwxdEw3QV9oRkRLUTk3NUQ0VG5IUG5pbXI1V2pqS1ZvZTgyalNtMWM4TSIsImF1ZCI6Ing1MDlfaGFzaDpMVEhsQm1yTjZXYzlvRTNUeEZacDQ3ZkVUNmlGQlFJaXdNSml1M0JMY3F3Iiwibm9uY2UiOiI1OGM0NGU3MS1iMWQ0LTRlN2EtYmRlNS0wNjRlZTVjYjNlZWQiLCJpYXQiOjE3NzA1NzA4MjB9.grkkzdj3o2dM60uMwLAaKE7qZwnA_M8kBVeq9aBYjaKKjKHZvdFoGJAgvRgqCzIm_lA_xnEm8iChe_Z1q3LdDA".getBytes());
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        return validator;
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        boolean attestationSignatureFound = false;
        boolean keyBindingSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.getSigningCertificate() != null) {
                attestationSignatureFound = true;
            } else if (signatureWrapper.getSigningCertificatePublicKey() != null) {
                keyBindingSignatureFound = true;
            }
        }
        assertTrue(attestationSignatureFound);
        assertTrue(keyBindingSignatureFound);
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // not present
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void validateSignerInformation(SignerInformationType signerInformation) {
        // skip
    }

    @Override
    protected boolean orphanSelectivelyDisclosableClaimsPresent() {
        return true;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
